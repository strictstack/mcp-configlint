/** This package has no network or subprocess implementation. */
export const NETWORK_POLICY = Object.freeze({ allow: Object.freeze([]), policy: null });

export function guardEgress() {
  const error = new Error('Outbound operations are disabled.');
  error.code = 'ERR_OFFLINE_POLICY';
  throw error;
}

export const denyEgress = guardEgress;
