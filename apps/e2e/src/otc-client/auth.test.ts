import { buildOtcSiweMessage, OtcClient } from '@nadohq/otc-client';
import {
  createDeterministicLinkedSignerPrivateKey,
  subaccountToHex,
  WalletClientWithAccount,
} from '@nadohq/shared';
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { createWalletClient, http, zeroAddress } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  assertNonEmptyString,
  assertNonNegativeInteger,
} from '../utils/assertions';
import { debugPrint } from '../utils/debugPrint';
import { delay } from '../utils/delay';
import { createTestContext } from '../utils/runWithContext';
import {
  TEST_DELAYS,
  TEST_SUBACCOUNT_NAME,
  TEST_TIMEOUTS,
} from '../utils/testConstants';
import { RunContext } from '../utils/types';

/** The login routes only admit approved web origins; a Node client has to send one itself. */
const TEST_ORIGIN = 'https://testnet.nado.xyz';

void describe('[otc-client]: auth', { timeout: TEST_TIMEOUTS.LONG }, () => {
  let tc: RunContext;
  let otc: OtcClient;
  let sender: string;

  before(() => {
    tc = createTestContext();
    otc = new OtcClient({ url: tc.endpoints.otc, origin: TEST_ORIGIN });
    sender = subaccountToHex({
      subaccountOwner: tc.walletClientAddress,
      subaccountName: TEST_SUBACCOUNT_NAME,
    });
  });

  void test('logs in with a signed nonce', async () => {
    const nonce = await otc.getAuthNonce({ sender });
    debugPrint('OTC auth nonce', nonce);

    assertNonEmptyString(nonce.nonce, 'nonce');
    assertNonNegativeInteger(nonce.issued_at_ms, 'issued_at_ms');
    assert.ok(nonce.expires_at_ms > nonce.issued_at_ms);

    const message = buildOtcSiweMessage({
      domain: new URL(TEST_ORIGIN).host,
      uri: TEST_ORIGIN,
      address: tc.walletClientAddress,
      chainId: tc.chainId,
      nonce: nonce.nonce,
      issuedAtMs: nonce.issued_at_ms,
      sender,
    });
    const signature = await tc.walletClient.signMessage({ message });

    const session = await otc.verifyAuth({ message, signature });
    debugPrint('OTC auth session', session);

    assert.equal(
      session.owner.toLowerCase(),
      tc.walletClientAddress.toLowerCase(),
    );
    assert.equal(session.sender.toLowerCase(), sender.toLowerCase());
    assert.equal(
      session.signer.toLowerCase(),
      tc.walletClientAddress.toLowerCase(),
    );
    assertNonNegativeInteger(session.expires_at_ms, 'expires_at_ms');
  });

  void test('rejects a reused nonce', async () => {
    const nonce = await otc.getAuthNonce({ sender });
    const message = buildOtcSiweMessage({
      domain: new URL(TEST_ORIGIN).host,
      uri: TEST_ORIGIN,
      address: tc.walletClientAddress,
      chainId: tc.chainId,
      nonce: nonce.nonce,
      issuedAtMs: nonce.issued_at_ms,
      sender,
    });
    const signature = await tc.walletClient.signMessage({ message });
    await otc.verifyAuth({ message, signature });

    await assert.rejects(otc.verifyAuth({ message, signature }));
  });

  void describe('with a linked signer', () => {
    let linkedSigner: WalletClientWithAccount;

    before(async () => {
      const privateKey = await createDeterministicLinkedSignerPrivateKey({
        chainId: tc.chainId,
        endpointAddress: tc.endpointAddr,
        walletClient: tc.walletClient,
        subaccountOwner: tc.walletClientAddress,
        subaccountName: TEST_SUBACCOUNT_NAME,
      });
      linkedSigner = createWalletClient({
        chain: tc.walletClient.chain,
        account: privateKeyToAccount(privateKey),
        transport: http(),
      });

      const result = await tc.engine.linkSigner({
        chainId: tc.chainId,
        signer: subaccountToHex({
          subaccountOwner: linkedSigner.account.address,
          subaccountName: '',
        }),
        subaccountOwner: tc.walletClientAddress,
        subaccountName: TEST_SUBACCOUNT_NAME,
        verifyingAddr: tc.endpointAddr,
      });
      assert.equal(result.status, 'success', 'linkSigner should succeed');
      // Let the link propagate before OTC checks it
      await delay(TEST_DELAYS.LONG);
    });

    after(async () => {
      await tc.engine.linkSigner({
        chainId: tc.chainId,
        signer: subaccountToHex({
          subaccountOwner: zeroAddress,
          subaccountName: '',
        }),
        subaccountOwner: tc.walletClientAddress,
        subaccountName: TEST_SUBACCOUNT_NAME,
        verifyingAddr: tc.endpointAddr,
      });
    });

    // The web app signs with the 1CT key so the owner wallet never sees a prompt
    void test('logs in with the linked signer', async () => {
      const nonce = await otc.getAuthNonce({ sender });
      const message = buildOtcSiweMessage({
        domain: new URL(TEST_ORIGIN).host,
        uri: TEST_ORIGIN,
        address: linkedSigner.account.address,
        chainId: tc.chainId,
        nonce: nonce.nonce,
        issuedAtMs: nonce.issued_at_ms,
        sender,
      });
      const signature = await linkedSigner.signMessage({ message });

      const session = await otc.verifyAuth({ message, signature });
      debugPrint('OTC auth session (linked signer)', session);

      assert.equal(
        session.owner.toLowerCase(),
        tc.walletClientAddress.toLowerCase(),
      );
      assert.equal(
        session.signer.toLowerCase(),
        linkedSigner.account.address.toLowerCase(),
      );
    });
  });
});
