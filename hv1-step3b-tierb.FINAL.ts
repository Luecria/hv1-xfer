// H-V1 manual step 3, Tier B (validation-h-v1.md step 3 + 2026-11-10 addendum):
// prove or disprove on-chain that the Velocity protocol vault's user — whose
// VaultOwned flag bit is missing (step 2: protocol-path user status byte 0 vs
// plain-path 32) — actually GETS PAID revenue share instead of forfeiting it
// in the settle_revenue_share sweep (the sweep branches on the BENEFICIARY
// user's is_vault_owned(): referrer branch
// programs/velocity/src/controller/revenue_share.rs:212, builder branch :274).
//
// This script is the accrual + settle half that hv1-step3-revenue-share.FINAL.ts
// left as TODO-ACCRUAL. It runs against the preserved validator ledger from
// steps 2/3 (state + spot market 0 initialized, genesis PythLazer oracle
// loaded, both vaults created, Tier A RevenueShare+Escrow initialized for both
// vault authorities). Per-anchor resolutions are in FILLED-TIERB.md.
//
// Flow (mirrors the repo's canonical LiteSVM flow, tests/velocity/referrer.ts,
// re-pointed at RPC per RUNBOOK.md — plain Connection/AnchorProvider, genesis
// oracle instead of setAccount mock oracles, instruction-level account layouts
// taken from the SDK builders, not improvised):
//   0. Preflight: state, oracle decode, mint authority, vault flag re-read.
//   1. Admin: widen the oracle guard rails (see FILLED-TIERB.md — the genesis
//      oracle's posted_slot is 1, so at any realistic validator slot the
//      default staleness windows reject it; the LiteSVM tests never face this
//      because their mock oracle is future-dated), enable builder codes
//      (settle_revenue_share rejects without it, keeper.rs:3215-3219).
//   2. Bootstrap perp market 0 on the genesis oracle if absent (curve updates
//      disabled, so the settle crank's reserve price reads the oracle with no
//      validity gate — controller/perp_pools.rs get_pnl_pool_drain_reserve_price).
//   3. Per vault (protocol primary, plain control): a fresh referee keypair
//      whose FIRST initialize_user names the vault's User (sub 0) + UserStats
//      as remaining accounts (handler sets stats.referrer = vault authority,
//      no referrer signature — user.rs:141-165); referee escrow init snapshots
//      that referrer (user.rs:461). A maker posts a resting post-only SHORT;
//      the referee posts a crossing LONG; the payer (filler) fills it. On the
//      fill, the taker fee's referrer share accrues into a referral row in the
//      REFEREE's escrow naming the vault authority as beneficiary
//      (controller/orders.rs — the AMM-path accrual and its match-path twin).
//   4. settle_pnl for the referee (moves the settled fee value into the perp
//      market's pnl pool, which funds the sweep), snapshot the vault's
//      RevenueShare, run the settle_revenue_share crank for the referee's
//      escrow with the step-3 remaining-accounts recipe, snapshot again.
//   5. Verdict: protocol vault's totalReferrerRewards + totalBuilderRewards
//      INCREASED across its crank while the plain control's stayed FLAT and
//      its referral row was cleared (forfeited) => hypothesisHolds.
//
// Env:
//   RPC_URL, PAYER_PATH, IDL_DIR, EVIDENCE_OUT   (as in steps 2/3)
//   PROTOCOL_VAULT  required   vault PDA from evidence-step2.json (.protocol.vault)
//   PLAIN_VAULT     optional   control vault PDA (.plain.vault); without it the
//                              paid-vs-forfeited comparison cannot complete and
//                              the verdict reports controlMissing
//   MARKET_INDEX    default 0  perp market index (spot quote market is always 0)
//   ORACLE_PUBKEY   REQUIRED   genesis-loaded PythLazer oracle account. No
//                              default is embedded on purpose: read it in the
//                              sandbox from ~/hv1/oracle-account.json (the
//                              RUNBOOK genesis step prints ORACLE_PUBKEY=...).
//                              A base58 string for it that circulated in
//                              session notes contains a '0' and does not
//                              decode — do not reuse it.
//   USDC_MINT       default Cnfmms3pLtn792qDiKGkNwg6p7CywLg8vgizS1VGmUY
//                              (mint created in step 2, authority = payer)

import * as anchor from '@coral-xyz/anchor';
import { Program, AnchorProvider, Wallet, BN } from '@coral-xyz/anchor';
import {
  Connection, Keypair, PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY,
  Transaction, sendAndConfirmTransaction,
} from '@solana/web3.js';
import {
  getOrCreateAssociatedTokenAccount, getMint, mintTo, TOKEN_PROGRAM_ID,
} from '@solana/spl-token';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const RPC_URL = process.env.RPC_URL ?? 'http://127.0.0.1:8899';
const PAYER_PATH = process.env.PAYER_PATH ?? join(homedir(), '.config/solana/id.json');
const IDL_DIR = process.env.IDL_DIR ?? './idl';
const EVIDENCE_OUT = process.env.EVIDENCE_OUT ?? './evidence-step3b.json';
const MARKET_INDEX = Number(process.env.MARKET_INDEX ?? '0');
if (!process.env.PROTOCOL_VAULT) throw new Error('PROTOCOL_VAULT env is required (see evidence-step2.json)');
const PROTOCOL_VAULT = new PublicKey(process.env.PROTOCOL_VAULT);
const PLAIN_VAULT = process.env.PLAIN_VAULT ? new PublicKey(process.env.PLAIN_VAULT) : null;
if (!process.env.ORACLE_PUBKEY) throw new Error('ORACLE_PUBKEY env is required (read it from ~/hv1/oracle-account.json in the sandbox — see header)');
const ORACLE_PUBKEY = new PublicKey(process.env.ORACLE_PUBKEY);
const USDC_MINT = new PublicKey(process.env.USDC_MINT ?? 'Cnfmms3pLtn792qDiKGkNwg6p7CywLg8vgizS1VGmUY');

const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(PAYER_PATH, 'utf8'))));
const connection = new Connection(RPC_URL, 'confirmed');
const provider = new AnchorProvider(connection, new Wallet(payer), { commitment: 'confirmed' });
anchor.setProvider(provider);
const velocity = new Program(JSON.parse(readFileSync(join(IDL_DIR, 'velocity.json'), 'utf8')), provider);
const VELOCITY_ID = velocity.programId;

const pda = (seeds: (Buffer | Uint8Array)[], programId: PublicKey) =>
  PublicKey.findProgramAddressSync(seeds, programId)[0];
const u16le = (n: number) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
// SDK encodeName (packages/sdk/src/userName.ts:17-27), copied from step 2:
// name bytes, then SPACE padding to 32.
const encodeName = (name: string) => {
  const bytes = Buffer.from(name, 'utf8');
  if (bytes.length > 32) throw new Error('name too long');
  const out = Buffer.alloc(32, 0x20);
  bytes.copy(out);
  return out;
};

const statePda = pda([Buffer.from('velocity_state')], VELOCITY_ID);
const userPda = (authority: PublicKey, subId = 0) =>
  pda([Buffer.from('user'), authority.toBuffer(), u16le(subId)], VELOCITY_ID);
const userStatsPda = (authority: PublicKey) =>
  pda([Buffer.from('user_stats'), authority.toBuffer()], VELOCITY_ID);
const revenueSharePda = (authority: PublicKey) =>
  pda([Buffer.from('REV_SHARE'), authority.toBuffer()], VELOCITY_ID);
const revenueShareEscrowPda = (authority: PublicKey) =>
  pda([Buffer.from('REV_ESCROW'), authority.toBuffer()], VELOCITY_ID);
const spotMarketPda = (i: number) => pda([Buffer.from('spot_market'), u16le(i)], VELOCITY_ID);
const spotMarketVaultPda = (i: number) =>
  pda([Buffer.from('spot_market_vault'), u16le(i)], VELOCITY_ID);
const perpMarketPda = (i: number) => pda([Buffer.from('perp_market'), u16le(i)], VELOCITY_ID);

const VAULT_OWNED_MASK = 0b00100000; // UserStatus::VaultOwned, state/user.rs (step 2)
const REFERRAL_ROW_FLAG = 0x04; // RevenueShareOrderBitFlag::Referral (sdk math/builder.ts)
const ESCROW_NUM_ORDERS = 3; // same value as Tier A / referrer.ts
const DEPOSIT_RAW = new BN(200_000_000); // 200 USDC (6 dp) per trading user
const TARGET_QUOTE_RAW = 100_000_000n; // aim for a $100 fill: fee and reward stay > 0

const log = (...args: unknown[]) => console.log(...args);
const exists = async (pk: PublicKey) => (await connection.getAccountInfo(pk)) !== null;

// JSON-safe rendering of decoded accounts / events for the evidence file.
function sanitize(v: unknown): unknown {
  if (v === null || v === undefined) return v;
  if (typeof v === 'bigint') return v.toString();
  if (BN.isBN(v)) return (v as BN).toString();
  if (v instanceof PublicKey) return v.toBase58();
  if (Array.isArray(v)) return v.map(sanitize);
  if (typeof v === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = sanitize(val);
    return out;
  }
  return v;
}

// Same snapshot shape as hv1-step3-revenue-share.FINAL.ts (kept byte-compatible
// so step-3 and step-3b evidence can be diffed directly).
async function snapshotRevenueShare(authority: PublicKey, label: string) {
  const rs = revenueSharePda(authority);
  const escrow = revenueShareEscrowPda(authority);
  const out: Record<string, unknown> = { label, authority: authority.toBase58(), revenueShare: rs.toBase58(), escrow: escrow.toBase58() };
  try {
    const acct: any = await velocity.account.revenueShare.fetch(rs);
    out.totalReferrerRewards = acct.totalReferrerRewards.toString();
    out.totalBuilderRewards = acct.totalBuilderRewards.toString();
  } catch { out.revenueShareExists = false; }
  out.escrowExists = (await connection.getAccountInfo(escrow)) !== null;
  log(label, JSON.stringify(out));
  return out;
}

// Tier A init (defensive reuse): only called when a vault's revenue-share
// accounts are missing, which the preserved ledger should already have.
async function initRevenueShareFor(authority: PublicKey) {
  const rsSig = await velocity.methods
    .initializeRevenueShare()
    .accounts({
      revenueShare: revenueSharePda(authority),
      authority,
      payer: payer.publicKey,
      rent: SYSVAR_RENT_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  const escrowSig = await velocity.methods
    .initializeRevenueShareEscrow(ESCROW_NUM_ORDERS)
    .accounts({
      escrow: revenueShareEscrowPda(authority),
      authority,
      userStats: userStatsPda(authority),
      state: statePda,
      payer: payer.publicKey,
      rent: SYSVAR_RENT_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .rpc();
  log('revenue-share init for', authority.toBase58(), { rsSig, escrowSig });
  return { rsSig, escrowSig };
}

async function fundSol(kp: PublicKey, lamports = 500_000_000) {
  const tx = new Transaction().add(
    SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: kp, lamports })
  );
  return sendAndConfirmTransaction(connection, tx, [payer], { commitment: 'confirmed' });
}

async function initUserStats(kp: Keypair) {
  return velocity.methods
    .initializeUserStats()
    .accounts({
      userStats: userStatsPda(kp.publicKey),
      state: statePda,
      authority: kp.publicKey,
      payer: kp.publicKey,
      rent: SYSVAR_RENT_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .signers([kp])
    .rpc();
}

async function initUser(kp: Keypair, name: string, referrer?: PublicKey) {
  const remainingAccounts = referrer
    ? [
        { pubkey: userPda(referrer, 0), isWritable: true, isSigner: false },
        { pubkey: userStatsPda(referrer), isWritable: true, isSigner: false },
      ]
    : [];
  return velocity.methods
    .initializeUser(0, Array.from(encodeName(name)))
    .accounts({
      user: userPda(kp.publicKey, 0),
      userStats: userStatsPda(kp.publicKey),
      state: statePda,
      authority: kp.publicKey,
      payer: kp.publicKey,
      rent: SYSVAR_RENT_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .remainingAccounts(remainingAccounts)
    .signers([kp])
    .rpc();
}

let spotVault: PublicKey = spotMarketVaultPda(0);
async function depositUsdc(kp: Keypair, amount: BN) {
  const ata = await getOrCreateAssociatedTokenAccount(connection, kp, USDC_MINT, kp.publicKey);
  const mintSig = await mintTo(connection, payer, USDC_MINT, ata.address, payer, BigInt(amount.toString()));
  const sig = await velocity.methods
    .deposit(0, amount, false)
    .accounts({
      state: statePda,
      user: userPda(kp.publicKey, 0),
      userStats: userStatsPda(kp.publicKey),
      authority: kp.publicKey,
      spotMarketVault: spotVault,
      userTokenAccount: ata.address,
      tokenProgram: TOKEN_PROGRAM_ID,
    })
    .signers([kp])
    .rpc();
  return { ata: ata.address.toBase58(), mintSig, sig };
}

// Best-effort event extraction (OrderActionRecord on fills,
// RevenueShareSettleRecord on the crank). Evidence only; never asserted on.
async function txEvents(sig: string) {
  try {
    const tx = await connection.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    const logs = tx?.meta?.logMessages ?? [];
    const parser = new anchor.EventParser(VELOCITY_ID, velocity.coder);
    const out: unknown[] = [];
    for (const ev of parser.parseLogs(logs)) out.push({ name: ev.name, data: sanitize(ev.data) });
    return out;
  } catch (e) {
    return [{ parseError: String(e) }];
  }
}

// Decoded escrow rows, rendered evidence-friendly.
async function escrowRows(authority: PublicKey) {
  const esc: any = await velocity.account.revenueShareEscrow.fetch(revenueShareEscrowPda(authority));
  const rows = (esc.orders as any[]).map((o: any) => ({
    feesAccrued: o.feesAccrued.toString(),
    orderId: o.orderId,
    feeTenthBps: o.feeTenthBps,
    marketIndex: o.marketIndex,
    subAccountId: o.subAccountId,
    builderIdx: o.builderIdx,
    bitFlags: o.bitFlags,
    isReferralRow: (o.bitFlags & REFERRAL_ROW_FLAG) !== 0,
    marketType: sanitize(o.marketType),
  }));
  return { referrer: esc.referrer.toBase58(), authority: esc.authority.toBase58(), rows };
}

const referralRowFor = (rows: { marketIndex: number; isReferralRow: boolean; feesAccrued: string }[]) =>
  rows.find((r) => r.isReferralRow && r.marketIndex === MARKET_INDEX);

// The maps prefix every trading instruction below shares. Layout follows the
// SDK's getRemainingAccounts output order — oracles, then spot markets, then
// perp markets (packages/sdk/src/core/remainingAccounts.ts). Spot market 0's
// oracle is the default pubkey (QuoteAsset) and is skipped, exactly as the
// SDK skips it.
const mapsPrefix = (spotWritable: boolean, perpWritable: boolean) => [
  { pubkey: ORACLE_PUBKEY, isWritable: false, isSigner: false },
  { pubkey: spotMarketPda(0), isWritable: spotWritable, isSigner: false },
  { pubkey: perpMarketPda(MARKET_INDEX), isWritable: perpWritable, isSigner: false },
];

function orderParams(direction: 'long' | 'short', postOnly: 'none' | 'mustPostOnly', userOrderId: number, base: BN, price: BN) {
  return {
    orderType: { limit: {} },
    marketType: { perp: {} },
    direction: direction === 'long' ? { long: {} } : { short: {} },
    userOrderId,
    baseAssetAmount: base,
    price,
    marketIndex: MARKET_INDEX,
    reduceOnly: false,
    postOnly: postOnly === 'none' ? { none: {} } : { mustPostOnly: {} },
    bitFlags: 0,
    maxTs: null,
    triggerPrice: null,
    triggerCondition: { above: {} },
    oraclePriceOffset: null,
    auctionDuration: null,
    auctionStartPrice: null,
    auctionEndPrice: null,
    builderIdx: null,
    builderFeeTenthBps: null,
  };
}

async function placeOrder(kp: Keypair, params: ReturnType<typeof orderParams>) {
  const sig = await velocity.methods
    .placePerpOrder(params as any)
    .accounts({ state: statePda, user: userPda(kp.publicKey, 0), authority: kp.publicKey })
    .remainingAccounts(mapsPrefix(false, false))
    .signers([kp])
    .rpc();
  const user: any = await velocity.account.user.fetch(userPda(kp.publicKey, 0));
  const order = (user.orders as any[]).find(
    (o: any) => o.userOrderId === params.userOrderId && o.marketIndex === MARKET_INDEX
  );
  if (!order) throw new Error(`placed order userOrderId=${params.userOrderId} not found on user ${kp.publicKey.toBase58()}`);
  return { sig, orderId: order.orderId as number };
}

// Permissionless PnL settle for the referee: moves the fill's settled fee
// value into the perp market's pnl pool, which is what funds the sweep
// (controller/revenue_share.rs — the sweep pays out of the pnl pool and skips
// rows the pool cannot cover). Named accounts + prefix mirror the SDK's
// settlePNLIx without a revenueShareEscrowMap (velocityClient.ts settlePNLIx).
async function settlePnl(kp: Keypair) {
  return velocity.methods
    .settlePnl(MARKET_INDEX)
    .accounts({
      state: statePda,
      user: userPda(kp.publicKey, 0),
      authority: payer.publicKey,
      spotMarketVault: spotMarketVaultPda(0),
    })
    .remainingAccounts(mapsPrefix(true, true))
    .rpc();
}

// The settle crank, identical named accounts to step 3's settleRevenueShare()
// (keeper.rs:4388-4406; spotMarketVault pinned to spot market 0). The caller
// supplies the remaining accounts: maps prefix (writable perp + writable quote
// spot), then numOwnerSubAccounts = 0 (a referral-only escrow has no open
// builder rows, so no owner sub-accounts — velocityClient.ts:13208-13347),
// then per beneficiary [User sub-0 writable, RevenueShare writable]
// (addBuilderToRemainingAccounts, velocityClient.ts:3573-3605; consumed
// on-chain by load_revenue_share_map, state/revenue_share_map.rs:130).
async function settleRevenueShare(
  escrowAuthority: PublicKey,
  remainingAccounts: { pubkey: PublicKey; isWritable: boolean; isSigner: boolean }[],
  numOwnerSubAccounts: number
) {
  const sig = await velocity.methods
    .settleRevenueShare(MARKET_INDEX, numOwnerSubAccounts)
    .accounts({
      state: statePda,
      escrowAuthority,
      revenueShareEscrow: revenueShareEscrowPda(escrowAuthority),
      spotMarketVault: spotMarketVaultPda(0),
    })
    .remainingAccounts(remainingAccounts)
    .rpc();
  log('settle_revenue_share tx:', sig);
  return sig;
}

// Shared maker (fresh keypair per run, funded once in main). Its resting
// post-only SHORT is what the referee's LONG crosses; fill fulfillment picks
// the Match method when the AMM cannot serve (stale-for-AMM oracle) and the
// referral row accrues identically on either path (controller/orders.rs).
const maker = Keypair.generate();
let makerOrderCounter = 10;

// One full leg: wire a referee to `vault`, accrue a referral row owed to the
// vault, crank the referee's escrow, and diff the vault's RevenueShare totals
// across the crank.
async function runLeg(vault: PublicKey, label: string, trade: { base: BN; price: BN }) {
  const leg: Record<string, unknown> = { label, vault: vault.toBase58() };
  const referee = Keypair.generate();
  leg.referee = referee.publicKey.toBase58();
  leg.fundSolTx = await fundSol(referee.publicKey);

  leg.initStatsTx = await initUserStats(referee);
  leg.initUserTx = await initUser(referee, label === 'protocol' ? 'Referee Proto' : 'Referee Plain', vault);
  const refStats: any = await velocity.account.userStats.fetch(userStatsPda(referee.publicKey));
  leg.refereeStatsReferrer = refStats.referrer.toBase58();
  if (!refStats.referrer.equals(vault)) {
    throw new Error(
      `referrer wiring failed for ${label}: referee stats.referrer=${leg.refereeStatsReferrer}, expected vault ${vault.toBase58()} ` +
        '(the handler silently defaults the referrer when the first remaining account does not parse as a User — user.rs:141-165)'
    );
  }

  // Referee's own revenue-share accounts; the escrow init snapshots
  // stats.referrer (the vault authority) into escrow.referrer (user.rs:461).
  leg.initRevenueShareTx = await velocity.methods
    .initializeRevenueShare()
    .accounts({
      revenueShare: revenueSharePda(referee.publicKey),
      authority: referee.publicKey,
      payer: referee.publicKey,
      rent: SYSVAR_RENT_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .signers([referee])
    .rpc();
  leg.initEscrowTx = await velocity.methods
    .initializeRevenueShareEscrow(ESCROW_NUM_ORDERS)
    .accounts({
      escrow: revenueShareEscrowPda(referee.publicKey),
      authority: referee.publicKey,
      userStats: userStatsPda(referee.publicKey),
      state: statePda,
      payer: referee.publicKey,
      rent: SYSVAR_RENT_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .signers([referee])
    .rpc();
  const escrowAfterInit = await escrowRows(referee.publicKey);
  leg.escrowReferrer = escrowAfterInit.referrer;
  if (escrowAfterInit.referrer !== vault.toBase58()) {
    throw new Error(`escrow referrer snapshot failed for ${label}: escrow.referrer=${escrowAfterInit.referrer}, expected ${vault.toBase58()}`);
  }

  // Keep the Standard referral rate deterministic: a vault stats account with
  // the accelerated bit set is switched back by the warm admin, mirroring
  // tests/velocity/referrer.ts:511-514 (the vault user may have been
  // auto-enrolled when the referee was created).
  const vaultStats: any = await velocity.account.userStats.fetch(userStatsPda(vault));
  leg.vaultAcceleratedStatusBefore = vaultStats.acceleratedReferralStatus;
  if (vaultStats.acceleratedReferralStatus !== 0) {
    leg.revokeAcceleratedTx = await velocity.methods
      .updateUserAcceleratedReferralStatus(false)
      .accounts({ admin: payer.publicKey, state: statePda, userStats: userStatsPda(vault) })
      .rpc();
  }

  leg.deposit = await depositUsdc(referee, DEPOSIT_RAW);

  // Maker rests a post-only SHORT at the trade price; referee crosses it LONG.
  makerOrderCounter += 1;
  const makerPlaced = await placeOrder(maker, orderParams('short', 'mustPostOnly', makerOrderCounter, trade.base, trade.price));
  leg.makerOrder = { userOrderId: makerOrderCounter, ...makerPlaced };
  const refereePlaced = await placeOrder(referee, orderParams('long', 'none', 1, trade.base, trade.price));
  leg.refereeOrder = { userOrderId: 1, ...refereePlaced };

  // Fill. Remaining accounts follow the SDK's getFillPerpOrderIx order
  // (velocityClient.ts:7679): maps prefix, maker (User, UserStats) pair, then
  // the taker's escrow + the referrer's UserStats read-only
  // (getTakerRevenueShareAccountMetas). The program consumes them in the same
  // order: load_maps, load_user_maps, escrow, referrer-accelerated status
  // (keeper.rs handle_fill_perp_order).
  leg.fillTx = await velocity.methods
    .fillPerpOrder(refereePlaced.orderId, null)
    .accounts({
      state: statePda,
      authority: payer.publicKey,
      filler: userPda(payer.publicKey, 0),
      fillerStats: userStatsPda(payer.publicKey),
      user: userPda(referee.publicKey, 0),
      userStats: userStatsPda(referee.publicKey),
    })
    .remainingAccounts([
      ...mapsPrefix(false, true),
      { pubkey: userPda(maker.publicKey, 0), isWritable: true, isSigner: false },
      { pubkey: userStatsPda(maker.publicKey), isWritable: true, isSigner: false },
      { pubkey: revenueShareEscrowPda(referee.publicKey), isWritable: true, isSigner: false },
      { pubkey: userStatsPda(vault), isWritable: false, isSigner: false },
    ])
    .rpc();
  leg.fillEvents = await txEvents(leg.fillTx as string);

  const rowsAfterFill = await escrowRows(referee.publicKey);
  leg.escrowRowsAfterFill = rowsAfterFill.rows;
  const row = referralRowFor(rowsAfterFill.rows);
  if (!row || BigInt(row.feesAccrued) <= 0n) {
    throw new Error(`no referral row with fees_accrued > 0 in the ${label} referee's escrow after the fill: ${JSON.stringify(rowsAfterFill.rows)}`);
  }
  leg.referralRowFeesAccrued = row.feesAccrued;

  try {
    const perp: any = await velocity.account.perpMarket.fetch(perpMarketPda(MARKET_INDEX));
    leg.pendingRevenueShareBeforeCrank = perp.pendingRevenueShare.toString();
  } catch { leg.pendingRevenueShareBeforeCrank = null; }

  // Fund the pnl pool from the referee's settled position, then crank. (The
  // crank can also pay without this when the pool is already funded —
  // tests/velocity/builderCodes.ts:1855 — but the canonical referrer flow
  // settles first, and an underfunded pool makes the sweep SKIP the row,
  // which would read as a false forfeit.)
  try {
    leg.settlePnlTx = await settlePnl(referee);
  } catch (e) {
    leg.settlePnlError = String(e);
  }

  leg.snapshotBeforeCrank = await snapshotRevenueShare(vault, `${label}-vault BEFORE-CRANK`);
  leg.settleTx = await settleRevenueShare(referee.publicKey, [
    ...mapsPrefix(true, true),
    { pubkey: userPda(vault, 0), isWritable: true, isSigner: false },
    { pubkey: revenueSharePda(vault), isWritable: true, isSigner: false },
  ], 0);
  leg.settleEvents = await txEvents(leg.settleTx as string);
  leg.snapshotAfterCrank = await snapshotRevenueShare(vault, `${label}-vault AFTER-CRANK`);

  const rowsAfterCrank = await escrowRows(referee.publicKey);
  leg.escrowRowsAfterCrank = rowsAfterCrank.rows;
  const rowAfter = referralRowFor(rowsAfterCrank.rows);
  leg.referralRowCleared = !rowAfter || BigInt(rowAfter.feesAccrued) === 0n;

  const before = leg.snapshotBeforeCrank as Record<string, unknown>;
  const after = leg.snapshotAfterCrank as Record<string, unknown>;
  leg.rewardsDelta = (
    BigInt(String(after.totalReferrerRewards ?? '0')) + BigInt(String(after.totalBuilderRewards ?? '0')) -
    (BigInt(String(before.totalReferrerRewards ?? '0')) + BigInt(String(before.totalBuilderRewards ?? '0')))
  ).toString();
  return leg;
}

async function main() {
  const evidence: Record<string, unknown> = {
    startedAt: new Date().toISOString(),
    rpcUrl: RPC_URL,
    marketIndex: MARKET_INDEX,
    protocolVault: PROTOCOL_VAULT.toBase58(),
    plainVault: PLAIN_VAULT?.toBase58() ?? null,
    oracle: ORACLE_PUBKEY.toBase58(),
    usdcMint: USDC_MINT.toBase58(),
    payer: payer.publicKey.toBase58(),
  };
  const txs: Record<string, unknown> = {};
  evidence.txs = txs;

  // ---- Preflight (no mutations) ----
  const pre: Record<string, unknown> = {};
  evidence.preflight = pre;
  if (!(await exists(statePda))) throw new Error('velocity State account missing — step 2 state init not on this ledger');
  let state: any = null;
  try { state = await velocity.account.state.fetch(statePda); } catch (e) { pre.stateFetchError = String(e); }
  if (state) {
    pre.coldAdmin = state.coldAdmin.toBase58();
    pre.warmAdmin = state.warmAdmin.toBase58();
    pre.numberOfMarkets = state.numberOfMarkets;
    pre.featureBitFlags = state.featureBitFlags;
    pre.oracleGuardRails = sanitize(state.oracleGuardRails);
    if (!state.coldAdmin.equals(payer.publicKey) && !state.warmAdmin.equals(payer.publicKey)) {
      throw new Error(`payer ${payer.publicKey.toBase58()} is neither cold nor warm admin of this State — admin steps would fail`);
    }
  }
  const oracleInfo = await connection.getAccountInfo(ORACLE_PUBKEY);
  if (!oracleInfo) throw new Error('genesis oracle account missing at ORACLE_PUBKEY');
  const od = oracleInfo.data;
  const priceRaw = od.readBigInt64LE(8);
  const postedSlot = od.readBigUInt64LE(24);
  const expo = od.readInt32LE(32);
  const confidence = od.readBigUInt64LE(40);
  // Scaled price in PRICE_PRECISION (1e6): the program divides the raw price
  // by 10^(-expo)/1e6 when the oracle precision exceeds PRICE_PRECISION
  // (state/oracle.rs get_pyth_price). General form: priceRaw * 10^(expo + 6).
  const shift = expo + 6;
  const pow10 = (n: number) => 10n ** BigInt(Math.abs(n));
  const scaledPrice = shift >= 0 ? priceRaw * pow10(shift) : priceRaw / pow10(shift);
  if (scaledPrice <= 0n) throw new Error(`decoded oracle scaled price is not positive: ${scaledPrice}`);
  const currentSlot = await connection.getSlot('confirmed');
  pre.oracleDecode = {
    priceRaw: priceRaw.toString(), postedSlot: postedSlot.toString(), expo,
    confidence: confidence.toString(), scaledPrice: scaledPrice.toString(),
    currentSlot, oracleAgeSlots: currentSlot - Number(postedSlot),
  };

  const mint = await getMint(connection, USDC_MINT);
  pre.mintAuthority = mint.mintAuthority?.toBase58() ?? null;
  if (!mint.mintAuthority || !mint.mintAuthority.equals(payer.publicKey)) {
    throw new Error('USDC_MINT mint authority is not the payer — deposits cannot be funded');
  }
  try {
    const spot: any = await velocity.account.spotMarket.fetch(spotMarketPda(0));
    spotVault = spot.vault as PublicKey;
  } catch { /* keep the PDA derivation */ }
  pre.spotMarketVault = spotVault.toBase58();

  // Re-read both vault users' flag bits (continuity with step 2's assertion).
  const flagBits: Record<string, unknown> = {};
  for (const [label, vault] of [['protocol', PROTOCOL_VAULT], ['plain', PLAIN_VAULT]] as const) {
    if (!vault) continue;
    const u: any = await velocity.account.user.fetch(userPda(vault, 0));
    flagBits[label] = { statusByte: u.status, vaultOwnedBit: (u.status & VAULT_OWNED_MASK) !== 0 };
    if (!(await exists(revenueSharePda(vault))) || !(await exists(revenueShareEscrowPda(vault)))) {
      txs[`tierA DefensiveInit ${label}`] = await initRevenueShareFor(vault);
    }
  }
  pre.vaultFlagBits = flagBits;

  // ---- Admin: oracle guard rails ----
  // The genesis oracle's posted_slot is 1. At any realistic slot the default
  // staleness windows (10 slots AMM / 120 margin, in legacy-slot units of
  // 400 ms — math/time.rs SlotClock) reject it for margin and fill actions.
  // The LiteSVM flows never hit this: their mock oracle is future-dated
  // (referrer.ts passes postedSlotOffset = 10000). Widening the margin window
  // to the program maximum (1,000,000 slots) and the AMM window to its i8 cap
  // (127) is the RPC equivalent; it changes only this test instance's
  // staleness policy, not the sweep logic under test. Price-divergence,
  // confidence and volatility rails are preserved from the live State.
  if (state) {
    const rails = state.oracleGuardRails;
    const marginNow = BigInt(rails.validity.slotsBeforeStaleForMargin.toString());
    if (marginNow < 1_000_000n) {
      const build = (amm: BN) => ({
        priceDivergence: {
          markOraclePercentDivergence: rails.priceDivergence.markOraclePercentDivergence,
          oracleTwap5minPercentDivergence: rails.priceDivergence.oracleTwap5minPercentDivergence,
        },
        validity: {
          slotsBeforeStaleForAmm: amm,
          slotsBeforeStaleForMargin: new BN(1_000_000),
          confidenceIntervalMaxSize: rails.validity.confidenceIntervalMaxSize,
          tooVolatileRatio: rails.validity.tooVolatileRatio,
        },
      });
      try {
        txs.updateOracleGuardRails = await velocity.methods
          .updateOracleGuardRails(build(new BN(127)) as any)
          .accounts({ admin: payer.publicKey, state: statePda })
          .rpc();
      } catch (e) {
        txs.updateOracleGuardRailsError = String(e);
        // Retry keeping the current AMM window: the Match fill route does not
        // need the AMM window, only the margin window.
        txs.updateOracleGuardRailsRetry = await velocity.methods
          .updateOracleGuardRails(build(rails.validity.slotsBeforeStaleForAmm) as any)
          .accounts({ admin: payer.publicKey, state: statePda })
          .rpc();
      }
      const stateAfter: any = await velocity.account.state.fetch(statePda);
      pre.oracleGuardRailsAfter = sanitize(stateAfter.oracleGuardRails);
    } else {
      pre.oracleGuardRailsNote = 'margin staleness window already at/above 1,000,000 slots; update skipped';
    }
  }

  // ---- Admin: builder codes (settle rejects without the feature) ----
  try {
    txs.updateFeatureBitFlagsBuilderCodes = await velocity.methods
      .updateFeatureBitFlagsBuilderCodes(true)
      .accounts({ admin: payer.publicKey, state: statePda })
      .rpc();
  } catch (e) { txs.updateFeatureBitFlagsBuilderCodesError = String(e); }

  // ---- Perp market bootstrap ----
  // Trade size: target a $100 quote so the taker fee (and therefore the
  // referrer share of it) is comfortably > 0 at any default fee tier.
  const baseRaw = TARGET_QUOTE_RAW * 1_000_000_000n / scaledPrice;
  if (baseRaw < 1n) throw new Error('computed base amount < 1 raw unit at this oracle price');
  const trade = { base: new BN(baseRaw.toString()), price: new BN(scaledPrice.toString()) };
  evidence.trade = {
    baseRaw: baseRaw.toString(),
    priceScaled: scaledPrice.toString(),
    expectedQuoteRaw: (baseRaw * scaledPrice / 1_000_000_000n).toString(),
  };
  if (!(await exists(perpMarketPda(MARKET_INDEX)))) {
    const reserve = new BN('50000000000000000'); // 5e13 * sqrt(PRICE_PRECISION), as in referrer.ts
    txs.initializePerpMarket = await velocity.methods
      .initializePerpMarket({
        marketIndex: MARKET_INDEX,
        ammBaseAssetReserve: reserve,
        ammQuoteAssetReserve: reserve,
        ammPeriodicity: new BN(3600),
        ammPegMultiplier: trade.price,
        oracleSource: { pythLazer: {} },
        contractTier: { speculative: {} },
        marginRatioInitial: 2000,
        marginRatioMaintenance: 500,
        liquidatorFee: 0,
        ifLiquidationFee: 10000,
        imfFactor: 0,
        activeStatus: true,
        baseSpread: 0,
        maxSpread: 142500,
        maxOpenInterest: new BN(0),
        maxRevenueWithdrawPerPeriod: new BN(0),
        quoteMaxInsurance: new BN(0),
        orderStepSize: new BN(1),
        orderTickSize: new BN(10),
        minOrderSize: new BN(1),
        concentrationCoefScale: new BN(1),
        curveUpdateIntensity: 0,
        ammJitIntensity: 0,
        name: Array.from(encodeName('TierB Perp Market')),
        lpPoolId: 0,
        fundingClampThreshold: 0,
        fundingRampSlope: 0,
      } as any)
      .accounts({
        admin: payer.publicKey,
        state: statePda,
        perpMarket: perpMarketPda(MARKET_INDEX),
        oracle: ORACLE_PUBKEY,
        rent: SYSVAR_RENT_PUBKEY,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  } else {
    const perp: any = await velocity.account.perpMarket.fetch(perpMarketPda(MARKET_INDEX));
    pre.existingPerpMarket = { oracle: perp.oracle.toBase58(), status: sanitize(perp.status) };
    if (!(perp.oracle as PublicKey).equals(ORACLE_PUBKEY)) {
      throw new Error(`perp market ${MARKET_INDEX} already exists on a different oracle (${perp.oracle.toBase58()}) — aborting rather than trading against it`);
    }
  }

  // ---- Filler (payer) and maker users ----
  if (!(await exists(userStatsPda(payer.publicKey)))) txs.payerInitStats = await initUserStats(payer);
  if (!(await exists(userPda(payer.publicKey, 0)))) txs.payerInitUser = await initUser(payer, 'Filler Payer');
  txs.payerDeposit = await depositUsdc(payer, DEPOSIT_RAW);
  txs.makerFundSol = await fundSol(maker.publicKey);
  txs.makerInitStats = await initUserStats(maker);
  txs.makerInitUser = await initUser(maker, 'Maker TierB');
  txs.makerDeposit = await depositUsdc(maker, DEPOSIT_RAW);
  evidence.maker = maker.publicKey.toBase58();

  // ---- Legs ----
  const legs: Record<string, unknown> = {};
  evidence.legs = legs;
  let protocolLeg: any = null;
  let plainLeg: any = null;
  try {
    protocolLeg = await runLeg(PROTOCOL_VAULT, 'protocol', trade);
    legs.protocol = protocolLeg;
  } catch (e) { legs.protocolError = String(e); }
  if (PLAIN_VAULT) {
    try {
      plainLeg = await runLeg(PLAIN_VAULT, 'plain', trade);
      legs.plain = plainLeg;
    } catch (e) { legs.plainError = String(e); }
  }

  // ---- Verdict ----
  // Aligned with validation-h-v1.md step 4 / the step-3 assertion: the
  // protocol vault's rewards total INCREASES across its crank (it was PAID,
  // so the missing VaultOwned bit did not protect it), while the plain
  // control's total stays FLAT and its referral row is cleared (forfeited via
  // the is_vault_owned() branch, controller/revenue_share.rs:212).
  const verdict: Record<string, unknown> = { controlMissing: !PLAIN_VAULT };
  if (protocolLeg) {
    verdict.protocolRewardsDelta = protocolLeg.rewardsDelta;
    verdict.protocolRowFeesAccrued = protocolLeg.referralRowFeesAccrued;
    verdict.protocolPaid = BigInt(protocolLeg.rewardsDelta as string) > 0n;
    verdict.protocolDeltaEqualsRowFees =
      BigInt(protocolLeg.rewardsDelta as string) === BigInt(protocolLeg.referralRowFeesAccrued as string);
    verdict.protocolRowCleared = protocolLeg.referralRowCleared;
  }
  if (plainLeg) {
    verdict.plainRewardsDelta = plainLeg.rewardsDelta;
    verdict.plainRowFeesAccrued = plainLeg.referralRowFeesAccrued;
    verdict.plainForfeited = BigInt(plainLeg.rewardsDelta as string) === 0n && plainLeg.referralRowCleared === true;
    verdict.plainRowCleared = plainLeg.referralRowCleared;
  }
  verdict.hypothesisHolds = Boolean(
    protocolLeg && plainLeg && verdict.protocolPaid && verdict.plainForfeited
  );
  evidence.verdict = verdict;
  log('VERDICT', JSON.stringify(verdict));

  writeFileSync(EVIDENCE_OUT, JSON.stringify(sanitize(evidence), null, 2));
  log('evidence written to', EVIDENCE_OUT);
  if (!verdict.hypothesisHolds) process.exitCode = 1;
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
