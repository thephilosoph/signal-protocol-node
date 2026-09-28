import { SenderKeyStateDTO, GroupStore } from './sender-keys';

/** Default {@link GroupStore}: plain Maps, no persistence (reference adapter). */
export class InMemoryGroupStore implements GroupStore {
  private keys = new Map<string, SenderKeyStateDTO>();

  async saveSenderKey(scope: string, groupId: string, ref: string, state: SenderKeyStateDTO): Promise<void> {
    this.keys.set(`${scope}|${groupId}|${ref}`, JSON.parse(JSON.stringify(state)));
  }

  async getSenderKey(scope: string, groupId: string, ref: string): Promise<SenderKeyStateDTO | null> {
    return this.keys.get(`${scope}|${groupId}|${ref}`) ?? null;
  }

  async deleteSenderKey(scope: string, groupId: string, ref: string): Promise<void> {
    this.keys.delete(`${scope}|${groupId}|${ref}`);
  }

  async listSenderKeys(scope: string, groupId: string): Promise<SenderKeyStateDTO[]> {
    const prefix = `${scope}|${groupId}|`;
    const out: SenderKeyStateDTO[] = [];
    for (const [key, value] of this.keys) {
      if (key.startsWith(prefix)) out.push(JSON.parse(JSON.stringify(value)));
    }
    return out;
  }
}
