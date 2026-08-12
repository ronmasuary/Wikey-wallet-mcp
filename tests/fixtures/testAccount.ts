// A stand-in resolved account for session tests.
//
// signPrompted requires an account (address + pubkey) because there is no
// default key — see SessionManager.signPrompted. Session tests exercise the
// bring-up/proof/rotation machinery rather than account resolution, so they
// pass this fixed pair; accounts.test.ts is what covers resolution itself.
export const TEST_ACCOUNT = {
  address: 'omnistar1testaccount000000',
  pubkey: 'VEVTVFBVQktFWQ==',
};
