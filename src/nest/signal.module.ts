import { Module, DynamicModule, Provider } from '@nestjs/common';
import { SignalClientConfig } from '../protocol/signal-client';
import { CryptoProvider } from '../crypto/crypto-provider';
import { SignalStore } from '../stores/signal-store';
import { InMemorySignalStore } from '../stores/in-memory-store';
import { GroupStore } from '../group/sender-keys';
import { SIGNAL_MODULE_OPTIONS } from './tokens';
import { SignalService } from './signal.service';

/**
 * Options for {@link SignalModule.forRoot} (synchronous).
 */
export interface SignalModuleOptions {
  /**
   * A shared store instance used for ALL users (scope-first interface — each
   * client scopes its keys by "<userId>.<deviceId>"). Ideal for KV adapters.
   */
  store?: SignalStore;

  /**
   * Or: a per-client store factory (receives the client scope
   * "<userId>.<deviceId>") for adapters that need dedicated instances.
   */
  storeFactory?: (scope: string) => SignalStore | Promise<SignalStore>;

  /** Persistence for Sender Keys group chains. Default: in-memory. */
  groupStore?: GroupStore;

  /** Custom crypto provider. Defaults to NodeCryptoProvider. */
  crypto?: CryptoProvider;

  /** Passed through to every SignalClient. */
  config?: SignalClientConfig;

  /** One-time prekeys generated per client on first use. Default 50. */
  defaultOneTimePreKeyCount?: number;
}

/**
 * Options for {@link SignalModule.forRootAsync} (factory-based, can inject
 * other providers such as ConfigService).
 */
export interface SignalModuleAsyncOptions {
  imports?: any[];
  inject?: any[];
  useFactory: (...args: any[]) => SignalModuleOptions | Promise<SignalModuleOptions>;
}

/**
 * NestJS integration (Dynamic Module pattern).
 *
 * @example
 * ```ts
 * @Module({
 *   imports: [SignalModule.forRoot({ store: new InMemorySignalStore() })],
 * })
 * export class AppModule {}
 * ```
 *
 * @example async config
 * ```ts
 * SignalModule.forRootAsync({
 *   imports: [ConfigModule],
 *   inject: [ConfigService],
 *   useFactory: (config: ConfigService) => ({
 *     storeFactory: (userId) => new PrismaSignalStore(prisma, userId),
 *   }),
 * })
 * ```
 */
@Module({})
export class SignalModule {
  static forRoot(options: SignalModuleOptions = {}): DynamicModule {
    const resolved: SignalModuleOptions = {
      ...options,
      store: options.storeFactory ? undefined : options.store ?? new InMemorySignalStore(),
    };
    const optionsProvider: Provider = {
      provide: SIGNAL_MODULE_OPTIONS,
      useValue: resolved,
    };
    return {
      module: SignalModule,
      providers: [optionsProvider, SignalService],
      exports: [SignalService, SIGNAL_MODULE_OPTIONS],
    };
  }

  static forRootAsync(asyncOptions: SignalModuleAsyncOptions): DynamicModule {
    const optionsProvider: Provider = {
      provide: SIGNAL_MODULE_OPTIONS,
      useFactory: asyncOptions.useFactory,
      inject: asyncOptions.inject ?? [],
    };
    return {
      module: SignalModule,
      imports: asyncOptions.imports ?? [],
      providers: [optionsProvider, SignalService],
      exports: [SignalService, SIGNAL_MODULE_OPTIONS],
    };
  }
}
