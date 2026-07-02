// AUTHORED-BY Claude Opus 4.8 (Fable unavailable) — re-review/upgrade candidate
//
// The NL→RDF UPGRADE-HANDSHAKE codec. Transport-agnostic: this encodes/decodes the
// "offer to upgrade to protocol <hash>" + "accept/decline" messages as structured
// plain objects AND as RDF (an A2A DataPart's payload, in AGORA/ANP terms) — but
// builds NO live transport / networking (the runtime carrier is a separate
// `@jeswr/solid-agent` package, per the roadmap). The codec preserves the
// `required` / no-silent-downgrade flag so a consumer can refuse NL fallback for a
// security-bearing step (the roadmap's cross-cutting rule). RDF is built/read via
// the GraphBuilder + the sanctioned parser — never hand-built triples / a bespoke
// parser.

import { parseRdf } from "@jeswr/fetch-rdf";
import type { DatasetCore, Quad } from "@rdfjs/types";
import { serialize } from "./serialize.js";
import type { HandshakeMessage, UpgradeOffer, UpgradeResponse } from "./types.js";
import { A2A, RDF_TYPE, XSD } from "./vocab.js";
import { GraphBuilder } from "./wrappers.js";

// Minted handshake terms (under the a2a: extension — no standard equivalent).
const A2A_UPGRADE_OFFER = `${A2A}UpgradeOffer` as const;
const A2A_UPGRADE_RESPONSE = `${A2A}UpgradeResponse` as const;
const A2A_PROTOCOL_HASH = `${A2A}protocolHash` as const;
const A2A_PROTOCOL_SOURCE = `${A2A}protocolSource` as const;
const A2A_PROTOCOL_NAME = `${A2A}protocolName` as const;
const A2A_REQUIRED = `${A2A}required` as const;
const A2A_ACCEPT = `${A2A}accept` as const;
const A2A_REASON = `${A2A}reason` as const;
const XSD_BOOLEAN = `${XSD}boolean` as const;

/** A subject IRI for an anonymous handshake message (a stable urn). */
const HANDSHAKE_SUBJECT = "urn:a2a:handshake" as const;

/**
 * Encode an offer to UPGRADE to the RDF/SHACL protocol `protocolHash`, fetchable
 * from `protocolSource`. When `required` is `true`, the offer is for a
 * security-bearing exchange that must NOT be silently downgraded to NL (see
 * {@link UpgradeOffer.required}). Returns the structured plain object (the
 * `kind`-discriminated DataPart payload).
 */
export function encodeUpgradeOffer(args: {
  protocolHash: string;
  protocolSource: string;
  required?: boolean;
  protocolName?: string;
}): UpgradeOffer {
  if (!args.protocolHash) {
    throw new TypeError("encodeUpgradeOffer: protocolHash is required.");
  }
  if (!args.protocolSource) {
    throw new TypeError("encodeUpgradeOffer: protocolSource is required.");
  }
  return {
    kind: "upgrade-offer",
    protocolHash: args.protocolHash,
    protocolSource: args.protocolSource,
    // Default to a NON-required (capability-only) upgrade. A security-bearing
    // caller sets required:true explicitly so silent downgrade is never the
    // default for a step that needs the signed/SHACL path.
    required: args.required === true,
    ...(args.protocolName !== undefined && { protocolName: args.protocolName }),
  };
}

/**
 * Decode + validate a structured upgrade-offer object. Returns the typed offer,
 * or throws a `TypeError` if the input is not a well-formed offer (a decode error
 * is a programming/protocol error, distinct from an ordinary decline).
 */
export function decodeUpgradeOffer(input: unknown): UpgradeOffer {
  if (
    typeof input !== "object" ||
    input === null ||
    (input as { kind?: unknown }).kind !== "upgrade-offer"
  ) {
    throw new TypeError("decodeUpgradeOffer: input is not an upgrade-offer.");
  }
  const o = input as Record<string, unknown>;
  if (typeof o.protocolHash !== "string" || typeof o.protocolSource !== "string") {
    throw new TypeError(
      "decodeUpgradeOffer: protocolHash and protocolSource are required strings.",
    );
  }
  // `required` is optional, but if PRESENT it must be a genuine boolean — a
  // malformed `required: "true"` must NOT be silently coerced to `false`
  // (optional), which would weaken the no-silent-downgrade guarantee.
  if (o.required !== undefined && typeof o.required !== "boolean") {
    throw new TypeError("decodeUpgradeOffer: required, when present, must be a boolean.");
  }
  return {
    kind: "upgrade-offer",
    protocolHash: o.protocolHash,
    protocolSource: o.protocolSource,
    required: o.required === true,
    ...(typeof o.protocolName === "string" && { protocolName: o.protocolName }),
  };
}

/** Encode a response (accept/decline) to an offer about `protocolHash`. */
export function encodeUpgradeResponse(args: {
  protocolHash: string;
  accept: boolean;
  reason?: string;
}): UpgradeResponse {
  if (!args.protocolHash) {
    throw new TypeError("encodeUpgradeResponse: protocolHash is required.");
  }
  if (typeof args.accept !== "boolean") {
    throw new TypeError("encodeUpgradeResponse: accept must be a boolean.");
  }
  return {
    kind: "upgrade-response",
    protocolHash: args.protocolHash,
    accept: args.accept,
    ...(args.reason !== undefined && { reason: args.reason }),
  };
}

/** Decode + validate a structured upgrade-response object. */
export function decodeUpgradeResponse(input: unknown): UpgradeResponse {
  if (
    typeof input !== "object" ||
    input === null ||
    (input as { kind?: unknown }).kind !== "upgrade-response"
  ) {
    throw new TypeError("decodeUpgradeResponse: input is not an upgrade-response.");
  }
  const o = input as Record<string, unknown>;
  if (typeof o.protocolHash !== "string" || typeof o.accept !== "boolean") {
    throw new TypeError(
      "decodeUpgradeResponse: protocolHash (string) and accept (boolean) are required.",
    );
  }
  return {
    kind: "upgrade-response",
    protocolHash: o.protocolHash,
    accept: o.accept,
    ...(typeof o.reason === "string" && { reason: o.reason }),
  };
}

/**
 * The no-silent-downgrade decision: given an offer and the peer's response, MAY
 * the exchange fall back to natural language?
 *
 * - The response MUST be about the SAME protocol as the offer — if
 *   `response.protocolHash !== offer.protocolHash`, the response is unrelated and
 *   CANNOT authorise a downgrade; returns `false` (fail closed). This forecloses an
 *   attack where an unrelated decline is used to justify NL fallback.
 * - If the offer is `required` and the peer DECLINED, the answer is `false` — a
 *   security-bearing exchange must NOT proceed in unsigned NL; the caller refuses.
 * - If the offer is `required` and the peer ACCEPTED, NL fallback is moot (they
 *   speak RDF/SHACL) — returns `false` (do not use NL).
 * - If the offer is NOT required, NL fallback is allowed when the peer declined the
 *   matching protocol.
 *
 * This is the codec-level expression of the roadmap's cross-cutting rule; it does
 * NOT enforce signatures — it just forecloses *silent* downgrade as the default.
 */
export function mayDowngradeToNl(offer: UpgradeOffer, response: UpgradeResponse): boolean {
  // The response must answer THIS offer; a mismatched hash never authorises NL.
  if (response.protocolHash !== offer.protocolHash) {
    return false;
  }
  if (offer.required) {
    return false;
  }
  return response.accept === false;
}

// --- RDF forms (the DataPart RDF payload) --------------------------------

/** The RDF (quads) form of a handshake message — for an RDF-native DataPart. */
export function handshakeToRdf(message: HandshakeMessage): Quad[] {
  const b = new GraphBuilder();
  if (message.kind === "upgrade-offer") {
    b.addIri(HANDSHAKE_SUBJECT, RDF_TYPE, A2A_UPGRADE_OFFER);
    b.addLiteral(HANDSHAKE_SUBJECT, A2A_PROTOCOL_HASH, message.protocolHash);
    b.addIri(HANDSHAKE_SUBJECT, A2A_PROTOCOL_SOURCE, message.protocolSource);
    b.addLiteral(HANDSHAKE_SUBJECT, A2A_REQUIRED, message.required ? "true" : "false", XSD_BOOLEAN);
    if (message.protocolName !== undefined) {
      b.addLiteral(HANDSHAKE_SUBJECT, A2A_PROTOCOL_NAME, message.protocolName);
    }
  } else {
    b.addIri(HANDSHAKE_SUBJECT, RDF_TYPE, A2A_UPGRADE_RESPONSE);
    b.addLiteral(HANDSHAKE_SUBJECT, A2A_PROTOCOL_HASH, message.protocolHash);
    b.addLiteral(HANDSHAKE_SUBJECT, A2A_ACCEPT, message.accept ? "true" : "false", XSD_BOOLEAN);
    if (message.reason !== undefined) {
      b.addLiteral(HANDSHAKE_SUBJECT, A2A_REASON, message.reason);
    }
  }
  return b.quads();
}

/** Serialise a handshake message to Turtle (default) or another n3 format. */
export function handshakeToTurtle(message: HandshakeMessage, format?: string): Promise<string> {
  return serialize(handshakeToRdf(message), format);
}

/**
 * Read a handshake message back from RDF (the round-trip). Accepts the parsed
 * quads/dataset OR a Turtle/JSON-LD string (parsed via the sanctioned
 * `@jeswr/fetch-rdf` parser). Returns the typed message, or `undefined` if the
 * graph carries no recognised handshake subject.
 *
 * The read is a fail-closed pipeline of four named security steps, each below:
 * coerce → find the SINGLE typed subject (reject ambiguity) → build
 * subject-scoped strict readers → project the one message type. No step ever
 * silently defaults a security-bearing flag (`required` / `accept`).
 */
export async function handshakeFromRdf(
  input: readonly Quad[] | DatasetCore | string,
  contentType = "text/turtle",
): Promise<HandshakeMessage | undefined> {
  const quads = await coerceToQuads(input, contentType);
  const found = findHandshakeSubject(quads);
  if (found === undefined) {
    return undefined;
  }
  const readers = subjectReaders(quads, found.subject);
  return found.isOffer ? projectOffer(readers) : projectResponse(readers);
}

/** Coerce a handshake input (quads / dataset / RDF text) to a quad array. */
async function coerceToQuads(
  input: readonly Quad[] | DatasetCore | string,
  contentType: string,
): Promise<Quad[]> {
  if (typeof input === "string") {
    const dataset = await parseRdf(input, contentType, {});
    return [...dataset] as Quad[];
  }
  if (Array.isArray(input)) {
    return [...input] as Quad[];
  }
  return [...(input as DatasetCore)] as Quad[];
}

/**
 * Find the SINGLE typed handshake subject. A well-formed message has EXACTLY ONE
 * subject typed `a2a:UpgradeOffer` XOR `a2a:UpgradeResponse`. An ambiguous graph
 * (zero, multiple, or a mixed offer+response) is REFUSED (`undefined`) rather
 * than splicing triples from unrelated subjects together — a spoofing guard. The
 * `rdf:type` object must be a NamedNode; a literal-valued `rdf:type
 * "…UpgradeOffer"` is malformed RDF and is not treated as a typed subject.
 */
function findHandshakeSubject(
  quads: readonly Quad[],
): { readonly isOffer: boolean; readonly subject: string } | undefined {
  const offerSubjects = new Set<string>();
  const responseSubjects = new Set<string>();
  for (const q of quads) {
    if (q.predicate.value !== RDF_TYPE || q.object.termType !== "NamedNode") {
      continue;
    }
    if (q.object.value === A2A_UPGRADE_OFFER) {
      offerSubjects.add(q.subject.value);
    } else if (q.object.value === A2A_UPGRADE_RESPONSE) {
      responseSubjects.add(q.subject.value);
    }
  }
  // Zero → no handshake; >1 (incl. a mixed offer+response) → ambiguous: refuse.
  if (offerSubjects.size + responseSubjects.size !== 1) {
    return undefined;
  }
  const isOffer = offerSubjects.size === 1;
  const subject = [...(isOffer ? offerSubjects : responseSubjects)][0];
  if (subject === undefined) {
    return undefined;
  }
  return { isOffer, subject };
}

/** Strict, subject-scoped predicate readers over a handshake graph. */
interface SubjectReaders {
  /** The single Literal object of `(subject, predicate, ?)`, or `undefined`. */
  readonly lit: (predicate: string) => string | undefined;
  /** The single NamedNode object of `(subject, predicate, ?)`, or `undefined`. */
  readonly iri: (predicate: string) => string | undefined;
  /**
   * A boolean predicate read STRICTLY: exactly one literal whose lexical value is
   * `"true"` or `"false"`. Anything else (missing, repeated, or a non-boolean
   * form) yields `undefined` so the caller REJECTS the graph rather than silently
   * defaulting a security-bearing flag (`required` / `accept`).
   */
  readonly strictBool: (predicate: string) => boolean | undefined;
}

/**
 * Build readers scoped to the single handshake `subject` (never global). If a
 * predicate appears more than once on the subject the graph is malformed and the
 * reader yields `undefined`.
 */
function subjectReaders(quads: readonly Quad[], subject: string): SubjectReaders {
  const single = (predicate: string, termType: "Literal" | "NamedNode"): string | undefined => {
    const matches = quads.filter(
      (q) =>
        q.subject.value === subject &&
        q.predicate.value === predicate &&
        q.object.termType === termType,
    );
    if (matches.length !== 1) {
      return undefined;
    }
    return matches[0]?.object.value;
  };
  const lit = (predicate: string): string | undefined => single(predicate, "Literal");
  return {
    lit,
    iri: (predicate: string): string | undefined => single(predicate, "NamedNode"),
    strictBool: (predicate: string): boolean | undefined => {
      const v = lit(predicate);
      if (v === "true") {
        return true;
      }
      if (v === "false") {
        return false;
      }
      return undefined;
    },
  };
}

/**
 * Project an {@link UpgradeOffer} from the subject readers. A missing/malformed
 * `protocolHash`, `protocolSource`, or `required` REJECTS the graph — a malformed
 * `required` must NOT be coerced to optional (the no-silent-downgrade guarantee).
 */
function projectOffer(r: SubjectReaders): UpgradeOffer | undefined {
  const protocolHash = r.lit(A2A_PROTOCOL_HASH);
  const protocolSource = r.iri(A2A_PROTOCOL_SOURCE);
  const required = r.strictBool(A2A_REQUIRED);
  if (protocolHash === undefined || protocolSource === undefined || required === undefined) {
    return undefined;
  }
  const name = r.lit(A2A_PROTOCOL_NAME);
  return {
    kind: "upgrade-offer",
    protocolHash,
    protocolSource,
    required,
    ...(name !== undefined && { protocolName: name }),
  };
}

/**
 * Project an {@link UpgradeResponse} from the subject readers. A missing/invalid
 * `accept` REJECTS the graph — never default to `accept: false`, which could
 * authorise NL fallback for an optional offer.
 */
function projectResponse(r: SubjectReaders): UpgradeResponse | undefined {
  const protocolHash = r.lit(A2A_PROTOCOL_HASH);
  const accept = r.strictBool(A2A_ACCEPT);
  if (protocolHash === undefined || accept === undefined) {
    return undefined;
  }
  const reason = r.lit(A2A_REASON);
  return {
    kind: "upgrade-response",
    protocolHash,
    accept,
    ...(reason !== undefined && { reason }),
  };
}
