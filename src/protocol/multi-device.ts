/**
 * Multi-device helpers (Phase 18).
 *
 * Address format is "<name>.<deviceId>". These helpers let applications treat
 * a *user* as the set of their devices: fan out to all devices, group session
 * addresses by user, and build addresses from user + device id.
 */

/** Build the address of one device of a user. */
export function addressOf(user: string, deviceId: number): string {
  if (typeof user !== 'string' || user.length === 0) {
    throw new Error('user must be a non-empty string');
  }
  if (!Number.isInteger(deviceId) || deviceId < 1) {
    throw new Error('deviceId must be a positive integer');
  }
  return `${user}.${deviceId}`;
}

/** Split an address into { user, deviceId }. Throws on malformed addresses. */
export function parseAddress(address: string): { user: string; deviceId: number } {
  const dot = address.lastIndexOf('.');
  if (dot <= 0 || dot === address.length - 1) {
    throw new Error(`Malformed address: "${address}" (expected "<name>.<deviceId>")`);
  }
  const deviceId = Number(address.slice(dot + 1));
  if (!Number.isInteger(deviceId) || deviceId < 1) {
    throw new Error(`Malformed address: "${address}" (device id must be a positive integer)`);
  }
  return { user: address.slice(0, dot), deviceId };
}

/** Group session addresses by their user (all devices of a user in one bucket). */
export function partitionAddressesByUser(addresses: string[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const address of addresses) {
    const { user } = parseAddress(address);
    (out[user] ??= []).push(address);
  }
  return out;
}
