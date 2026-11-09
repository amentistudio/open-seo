// Private, encrypted Alchemy state store for self-hosted deploys from CI.
//
// Upstream's `Cloudflare.state()` deploys an `alchemy-state-store` Worker that
// must be reachable on its public workers.dev URL and needs Secrets Store
// access. This store needs neither: the whole state is ONE AES-256-GCM
// encrypted object in a private R2 bucket, read and written through the
// Cloudflare REST API with the same CLOUDFLARE_API_TOKEN the deploy already
// uses (Workers R2 Storage Edit). Nothing is ever served publicly.
//
// Selected in alchemy.run.ts with OPENSEO_STATE_STORE=r2. Reads from
// process.env (the state layer is built before `--env-file` config applies):
//   CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID   — Cloudflare REST access
//   OPENSEO_STATE_BUCKET                          — private R2 bucket name
//   OPENSEO_STATE_KEY   (optional)                — object key, default
//                                                   "alchemy-state.enc.json"
//   ALCHEMY_STATE_PASSWORD                        — ≥32 chars; encrypts state
//                                                   (it holds Worker secrets)
//
// Concurrent deploys are not locked here: serialize them (the GitHub workflow
// uses a concurrency group).
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import {
  encodeState,
  reviveState,
  State,
  StateStoreError,
  type PersistedState,
  type ReplacedResourceState,
  type StateService,
} from "alchemy/State";
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";

const STATE_STORE_VERSION = 1;

type StageData = { resources: Record<string, unknown>; output?: unknown };
type StateDoc = {
  version: 1;
  stacks: Record<string, Record<string, StageData>>;
};
type Envelope = {
  v: 1;
  alg: "aes-256-gcm/scrypt";
  salt: string;
  iv: string;
  tag: string;
  data: string;
};

const requireEnv = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`R2 state store: ${name} is not set.`);
  return value;
};

const deriveKey = (password: string, salt: Buffer) =>
  scryptSync(password, salt, 32, {
    N: 2 ** 15,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });

const encryptDoc = (doc: StateDoc, password: string): Envelope => {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", deriveKey(password, salt), iv);
  const data = Buffer.concat([
    cipher.update(JSON.stringify(doc), "utf8"),
    cipher.final(),
  ]);
  return {
    v: 1,
    alg: "aes-256-gcm/scrypt",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: data.toString("base64"),
  };
};

const decryptDoc = (envelope: Envelope, password: string): StateDoc => {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    deriveKey(password, Buffer.from(envelope.salt, "base64")),
    Buffer.from(envelope.iv, "base64"),
  );
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(envelope.data, "base64")),
    decipher.final(),
  ]).toString("utf8");
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- ciphertext decrypts to this store's own document
  return JSON.parse(plain) as StateDoc;
};

const r2StateConfig = () => {
  const password = requireEnv("ALCHEMY_STATE_PASSWORD");
  if (password.length < 32) {
    throw new Error(
      "R2 state store: ALCHEMY_STATE_PASSWORD must be at least 32 characters.",
    );
  }
  const accountId = requireEnv("CLOUDFLARE_ACCOUNT_ID");
  const bucket = requireEnv("OPENSEO_STATE_BUCKET");
  const key = process.env.OPENSEO_STATE_KEY?.trim() || "alchemy-state.enc.json";
  return {
    password,
    token: requireEnv("CLOUDFLARE_API_TOKEN"),
    url: `https://api.cloudflare.com/client/v4/accounts/${accountId}/r2/buckets/${encodeURIComponent(bucket)}/objects/${key.split("/").map(encodeURIComponent).join("/")}`,
  };
};

export const readStateDoc = async (
  config = r2StateConfig(),
): Promise<StateDoc> => {
  const response = await fetch(config.url, {
    headers: { Authorization: `Bearer ${config.token}` },
  });
  if (response.status === 404) return { version: 1, stacks: {} };
  if (!response.ok) {
    throw new Error(
      `R2 state store: GET failed with HTTP ${response.status}: ${(await response.text()).slice(0, 500)}`,
    );
  }
  return decryptDoc(await response.json(), config.password);
};

export const writeStateDoc = async (
  doc: StateDoc,
  config = r2StateConfig(),
): Promise<void> => {
  const response = await fetch(config.url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${config.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(encryptDoc(doc, config.password)),
  });
  if (!response.ok) {
    throw new Error(
      `R2 state store: PUT failed with HTTP ${response.status}: ${(await response.text()).slice(0, 500)}`,
    );
  }
};

const toError = (message: string) => (cause: unknown) =>
  new StateStoreError({
    message: `${message}: ${cause instanceof Error ? cause.message : String(cause)}`,
    cause: cause instanceof Error ? cause : undefined,
  });

// Values are kept in their encoded (JSON) form and revived on every read, so
// callers never share mutable objects with the store.
const revive = <T>(encoded: unknown): T | undefined =>
  encoded === undefined
    ? undefined
    : // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- encodeState's JSON form, revived on each read
      (JSON.parse(JSON.stringify(encoded), reviveState) as T);

const makeR2State = Effect.tryPromise({
  try: async (): Promise<StateService> => {
    const config = r2StateConfig();
    const doc = await readStateDoc(config);
    // Serialize writes; each write uploads the latest full snapshot.
    let queue: Promise<void> = Promise.resolve();
    const flush = () => {
      const next = queue.then(() => writeStateDoc(doc, config));
      queue = next.catch(() => undefined);
      return next;
    };
    const stageData = (stack: string, stage: string, create: boolean) => {
      const stages =
        doc.stacks[stack] ?? (create ? (doc.stacks[stack] = {}) : undefined);
      if (!stages) return undefined;
      return (
        stages[stage] ??
        (create ? (stages[stage] = { resources: {} }) : undefined)
      );
    };
    const write = <T>(mutate: () => T) =>
      Effect.tryPromise({
        try: async () => {
          const result = mutate();
          await flush();
          return result;
        },
        catch: toError("R2 state store write failed"),
      });

    const state: StateService = {
      id: "openseo-r2",
      getVersion: () => Effect.succeed(STATE_STORE_VERSION),
      listStacks: () => Effect.sync(() => Object.keys(doc.stacks)),
      listStages: (stack) =>
        Effect.sync(() => Object.keys(doc.stacks[stack] ?? {})),
      get: ({ stack, stage, fqn }) =>
        Effect.sync(() =>
          revive<PersistedState>(
            stageData(stack, stage, false)?.resources[fqn],
          ),
        ),
      getReplacedResources: ({ stack, stage }) =>
        Effect.sync(() =>
          Object.values(stageData(stack, stage, false)?.resources ?? {})
            .map((value) => revive<ReplacedResourceState>(value))
            .filter(
              (value): value is ReplacedResourceState =>
                value?.status === "replaced",
            ),
        ),
      set: (request) =>
        write(() => {
          stageData(request.stack, request.stage, true)!.resources[
            request.fqn
          ] = encodeState(request.value);
          return request.value;
        }),
      delete: ({ stack, stage, fqn }) =>
        write(() => {
          const data = stageData(stack, stage, false);
          if (data) delete data.resources[fqn];
        }),
      deleteStack: ({ stack, stage }) =>
        write(() => {
          if (stage === undefined) delete doc.stacks[stack];
          else if (doc.stacks[stack]) delete doc.stacks[stack][stage];
        }),
      list: ({ stack, stage }) =>
        Effect.sync(() =>
          Object.keys(stageData(stack, stage, false)?.resources ?? {}),
        ),
      getOutput: ({ stack, stage }) =>
        Effect.sync(() => revive(stageData(stack, stage, false)?.output)),
      setOutput: (request) =>
        write(() => {
          stageData(request.stack, request.stage, true)!.output = encodeState(
            request.value,
          );
          return request.value;
        }),
    };
    return state;
  },
  catch: toError("R2 state store init failed"),
}).pipe(Effect.orDie);

export const r2State = () =>
  Layer.effect(
    State,
    Effect.gen(function* () {
      return yield* Effect.cached(makeR2State);
    }),
  );
