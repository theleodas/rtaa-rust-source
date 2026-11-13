//! RTAA / RTAA+ on BLS12-381 (zkcrypto `bls12_381` crate, RFC 9380 hash-to-curve).
//! Reproduces the attack/repair tests and the cost measurements of the poster paper.
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, Scalar};
use ff::Field;
use group::Curve;
use rand::{thread_rng, RngCore};
use sha2::{Digest, Sha512};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

static MILLER: AtomicUsize = AtomicUsize::new(0);
static FINALEXP: AtomicUsize = AtomicUsize::new(0);
fn counts() -> (usize, usize) { (MILLER.load(Relaxed), FINALEXP.load(Relaxed)) }
fn reset() { MILLER.store(0, Relaxed); FINALEXP.store(0, Relaxed); }

const GID: &[u8] = b"grp0";
const RND: u64 = 1;

fn h2s(parts: &[&[u8]]) -> Scalar {
    let mut h = Sha512::new();
    for p in parts { h.update(p); }
    let d = h.finalize();
    let mut a = [0u8; 64];
    a.copy_from_slice(&d);
    Scalar::from_bytes_wide(&a)
}
fn h2g1(dst: &[u8], msg: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, dst)
}
fn rs() -> Scalar { Scalar::random(&mut thread_rng()) }
fn g1() -> G1Projective { G1Projective::generator() }
fn g2() -> G2Projective { G2Projective::generator() }

fn msg0(id: usize) -> Vec<u8> {
    let mut m = GID.to_vec(); m.extend(RND.to_be_bytes()); m.extend((id as u64).to_be_bytes()); m
}
fn h0(id: usize) -> G1Projective { h2g1(b"RTAA-H0", &msg0(id)) }
fn h3(e: &Entry, bind_tag: bool) -> G1Projective {
    let mut m = msg0(e.id); m.extend(e.w.to_bytes());
    if bind_tag { m.extend(e.tag.to_affine().to_compressed()); }
    h2g1(b"RTAA-H3", &m)
}

#[derive(Clone)]
struct Entry {
    id: usize,
    pk: G2Projective,
    sk: Scalar,
    w: Scalar,
    tag: G1Projective,
    rho: G1Projective,     // corrected: over (ID,w,tau)
    rho_old: G1Projective, // original: over (ID,w)
}
fn term(e: &Entry) -> G1Projective { h0(e.id) + g1() * e.w }

fn pairing_check(pairs: &[(G1Affine, G2Affine)]) -> bool {
    MILLER.fetch_add(pairs.len(), Relaxed); FINALEXP.fetch_add(1, Relaxed);
    let prep: Vec<G2Prepared> = pairs.iter().map(|(_, q)| G2Prepared::from(*q)).collect();
    let refs: Vec<(&G1Affine, &G2Prepared)> = pairs.iter().zip(prep.iter()).map(|((p, _), q)| (p, q)).collect();
    multi_miller_loop(&refs).final_exponentiation() == Gt::identity()
}
fn sum_tags(es: &[Entry]) -> G1Projective { es.iter().fold(G1Projective::identity(), |a, e| a + e.tag) }

/// e(sum tau, g2) == prod e(term_i, PK_i): mu+1 Miller loops, one final exponentiation.
fn auth_check(es: &[Entry]) -> bool {
    let mut pairs = vec![(sum_tags(es).to_affine(), g2().to_affine())];
    for e in es { pairs.push(((-term(e)).to_affine(), e.pk.to_affine())); }
    pairing_check(&pairs)
}
fn audit_one(e: &Entry, bind: bool) -> bool {
    let rho = if bind { e.rho } else { e.rho_old };
    pairing_check(&[(rho.to_affine(), g2().to_affine()), ((-h3(e, bind)).to_affine(), e.pk.to_affine())])
}
fn audit_batch(es: &[Entry], bind: bool) -> bool {
    let mut rng = thread_rng();
    let cs: Vec<Scalar> = es.iter().map(|_| Scalar::from(rng.next_u64() | 1)).collect();
    let mut s = G1Projective::identity();
    for (c, e) in cs.iter().zip(es) { s += (if bind { e.rho } else { e.rho_old }) * c; }
    let mut pairs = vec![(s.to_affine(), g2().to_affine())];
    for (c, e) in cs.iter().zip(es) { pairs.push(((-(h3(e, bind) * c)).to_affine(), e.pk.to_affine())); }
    pairing_check(&pairs)
}
fn invalid_set(es: &[Entry], batched: bool) -> Vec<usize> {
    if es.is_empty() { return vec![]; }
    if batched {
        if audit_batch(es, true) { return vec![]; }
        if es.len() == 1 { return vec![es[0].id]; }
        let m = es.len() / 2;
        let mut a = invalid_set(&es[..m], true);
        a.extend(invalid_set(&es[m..], true));
        a
    } else {
        es.iter().filter(|e| !audit_one(e, true)).map(|e| e.id).collect()
    }
}
/// Hybrid: one batch test; if it passes no tag is invalid, otherwise fall back to per-party audits.
fn invalid_set_hybrid(es: &[Entry]) -> Vec<usize> {
    if audit_batch(es, true) { vec![] } else { invalid_set(es, false) }
}
fn judge_plus_hybrid(es: &[Entry]) -> Option<usize> {
    let bad = invalid_set_hybrid(es);
    let v: Vec<Entry> = es.iter().filter(|e| !bad.contains(&e.id)).cloned().collect();
    if v.is_empty() || auth_check(&v) { return None; }
    Some(judge_base(&v))
}
fn judge_base(es: &[Entry]) -> usize {
    if es.len() == 1 { return es[0].id; }
    let m = es.len() / 2;
    if !auth_check(&es[..m]) { judge_base(&es[..m]) } else { judge_base(&es[m..]) }
}
fn judge_plus_orig(es: &[Entry]) -> usize {
    for e in es { if !audit_one(e, false) { return e.id; } }
    judge_base(es)
}
fn judge_plus_fixed(es: &[Entry], batched: bool) -> Option<usize> {
    let bad = invalid_set(es, batched);
    let v: Vec<Entry> = es.iter().filter(|e| !bad.contains(&e.id)).cloned().collect();
    if v.is_empty() || auth_check(&v) { return None; }
    Some(judge_base(&v))
}

struct Round { es: Vec<Entry>, gammas: Vec<G1Projective>, ms: Vec<Vec<Scalar>>, tkg_s: f64, auth_s: f64 }

/// Pedersen-VSS threshold round key (ell dealers, threshold t) and one report per device.
fn make_round(mu: usize, k: usize, ell: usize, t: usize) -> Round {
    let h = g1() * rs();
    let t0 = Instant::now();
    let polys: Vec<(Vec<Scalar>, Vec<Scalar>)> = (0..ell).map(|_| ((0..t).map(|_| rs()).collect(), (0..t).map(|_| rs()).collect())).collect();
    let comms: Vec<Vec<G1Projective>> = polys.iter().map(|(a, b)| (0..t).map(|u| g1() * a[u] + h * b[u]).collect()).collect();
    let eval = |c: &Vec<Scalar>, x: u64| -> Scalar {
        let xs = Scalar::from(x); let mut p = Scalar::one(); let mut s = Scalar::zero();
        for cu in c { s += *cu * p; p *= xs; } s };
    for x in 1..=ell as u64 { // every party verifies every dealer's share against the commitments
        for (d, (a, b)) in polys.iter().enumerate() {
            let (sa, sb) = (eval(a, x), eval(b, x));
            let mut rhs = G1Projective::identity(); let mut p = Scalar::one(); let xs = Scalar::from(x);
            for u in 0..t { rhs += comms[d][u] * p; p *= xs; }
            assert!(g1() * sa + h * sb == rhs);
        }
    }
    // t parties reconstruct theta from their summed shares (Lagrange at 0)
    let pts: Vec<u64> = (1..=t as u64).collect();
    let mut theta = Scalar::zero();
    for &i in &pts {
        let si: Scalar = polys.iter().map(|(a, _)| eval(a, i)).fold(Scalar::zero(), |x, y| x + y);
        let (mut num, mut den) = (Scalar::one(), Scalar::one());
        for &j in &pts { if j != i { num *= Scalar::from(j); den *= Scalar::from(j) - Scalar::from(i); } }
        theta += si * num * den.invert().unwrap();
    }
    assert!(theta == polys.iter().fold(Scalar::zero(), |x, (a, _)| x + a[0]));
    let alpha = h2s(&[&theta.to_bytes(), &RND.to_be_bytes(), GID]);
    let mut gammas = vec![]; let mut pw = Scalar::one();
    for _ in 0..k { pw *= alpha; gammas.push(g1() * pw); }
    let tkg_s = t0.elapsed().as_secs_f64();

    let mut es = vec![]; let mut ms = vec![]; let mut auth_total = 0.0;
    for id in 0..mu {
        let sk = rs(); let pk = g2() * sk;
        let t1 = Instant::now();
        let m: Vec<Scalar> = (0..k).map(|_| rs()).collect();
        let (mut w, mut p) = (Scalar::zero(), Scalar::one());
        for mj in &m { p *= alpha; w += *mj * p; }
        let mut e = Entry { id, pk, sk, w, tag: G1Projective::identity(), rho: G1Projective::identity(), rho_old: G1Projective::identity() };
        e.tag = term(&e) * sk;
        e.rho = h3(&e, true) * sk;
        e.rho_old = h3(&e, false) * sk;
        auth_total += t1.elapsed().as_secs_f64();
        es.push(e); ms.push(m);
    }
    Round { es, gammas, ms, tkg_s, auth_s: auth_total / mu as f64 }
}

fn verify_full(r: &Round) -> bool {
    let mut ids: Vec<usize> = r.es.iter().map(|e| e.id).collect(); ids.sort(); ids.dedup();
    if ids.len() != r.es.len() { return false; }
    let k = r.gammas.len();
    let mut lhs = G1Projective::identity();
    for j in 0..k {
        let mj = r.ms.iter().fold(Scalar::zero(), |a, m| a + m[j]);
        lhs += r.gammas[j] * mj;
    }
    let wsum = r.es.iter().fold(Scalar::zero(), |a, e| a + e.w);
    lhs == g1() * wsum && auth_check(&r.es)
}

fn name(o: Option<usize>) -> String { o.map_or("bot".into(), |i| format!("P{i}")) }

fn security() {
    let r = make_round(4, 20, 5, 3);
    assert!(verify_full(&r), "honest round must verify");
    println!("attack,verify_rejects,base_judge,rtaa_plus_original,rtaa_plus_fixed,rtaa_plus_fixed_batched");
    for kind in ["swap_w", "sub_tau", "sub_tau_garbage_rho", "swap_tau", "garbage_rho", "malicious_P2"] {
        let mut es = r.es.clone();
        match kind {
            "swap_w" => { let (a, b) = (es[0].w, es[1].w); es[0].w = b; es[1].w = a; }
            "sub_tau" => es[0].tag = g1() * rs(),
            "sub_tau_garbage_rho" => { es[0].tag = g1() * rs(); es[0].rho = g1() * rs(); es[0].rho_old = g1() * rs(); }
            "swap_tau" => { let (a, b) = (es[0].tag, es[1].tag); es[0].tag = b; es[1].tag = a; }
            "garbage_rho" => { es[0].rho = g1() * rs(); es[0].rho_old = g1() * rs(); }
            _ => { es[2].tag = g1() * rs(); let e = es[2].clone(); es[2].rho = h3(&e, true) * es[2].sk; es[2].rho_old = h3(&e, false) * es[2].sk; }
        }
        let rej = !auth_check(&es);
        println!("{kind},{rej},P{},P{},{},{}", judge_base(&es), judge_plus_orig(&es),
                 name(judge_plus_fixed(&es, false)), name(judge_plus_fixed(&es, true)));
    }
}

fn median(mut v: Vec<f64>) -> f64 { v.sort_by(|a, b| a.partial_cmp(b).unwrap()); v[v.len() / 2] }

fn timing() {
    println!("mu,tkg_s,auth_per_device_s,verify_s,base_judge_s,plus_perparty_s,plus_batched_s,culprit_ok");
    for mu in [5usize, 10, 20, 40, 80, 160, 320] {
        let r = make_round(mu, 20, 5, 3);
        let reps = if mu <= 80 { 7 } else { 3 };
        let mut mal = r.es.clone(); let j = mu / 2;
        mal[j].tag = g1() * rs();
        let e = mal[j].clone(); mal[j].rho = h3(&e, true) * mal[j].sk;
        let t = |f: &dyn Fn() -> bool| median((0..reps).map(|_| { let s = Instant::now(); assert!(f()); s.elapsed().as_secs_f64() }).collect());
        let ver = t(&|| verify_full(&r));
        let jb = t(&|| judge_base(&mal) == j);
        let jp = t(&|| judge_plus_fixed(&mal, false) == Some(j));
        let jq = t(&|| judge_plus_fixed(&mal, true) == Some(j));
        println!("{mu},{:.6},{:.6},{:.6},{:.6},{:.6},{:.6},true", r.tkg_s, r.auth_s, ver, jb, jp, jq);
    }
}

fn tamper_tag(es: &mut Vec<Entry>, j: usize) {
    es[j].tag = g1() * rs();
    let e = es[j].clone(); es[j].rho = h3(&e, true) * es[j].sk;
}

fn pairing_counts() {
    println!("mu,verify_miller,verify_fe,base_miller,base_fe,pp_miller,pp_fe,batch_miller,batch_fe");
    for mu in [5usize, 10, 20, 40, 80, 160, 320] {
        let r = make_round(mu, 20, 5, 3);
        let mut mal = r.es.clone(); tamper_tag(&mut mal, mu / 2);
        reset(); assert!(auth_check(&r.es)); let v = counts();
        reset(); judge_base(&mal); let b = counts();
        reset(); judge_plus_fixed(&mal, false); let p = counts();
        reset(); judge_plus_fixed(&mal, true); let q = counts();
        println!("{mu},{},{},{},{},{},{},{},{}", v.0, v.1, b.0, b.1, p.0, p.1, q.0, q.1);
    }
}

fn ksweep() {
    println!("k,auth_per_device_s,verify_s,tkg_s");
    for k in [5usize, 10, 20, 40, 80, 160, 320] {
        let r = make_round(40, k, 5, 3);
        let ver = median((0..5).map(|_| { let s = Instant::now(); assert!(verify_full(&r)); s.elapsed().as_secs_f64() }).collect());
        println!("{k},{:.6},{:.6},{:.6}", r.auth_s, ver, r.tkg_s);
    }
}

fn tkgsweep() {
    println!("ell,t,tkg_s");
    for (l, t) in [(3usize, 2usize), (5, 3), (7, 4), (10, 6), (15, 8), (20, 11)] {
        let v: Vec<f64> = (0..3).map(|_| make_round(1, 20, l, t).tkg_s).collect();
        println!("{l},{t},{:.6}", median(v));
    }
}

fn invalid_rho() {
    println!("invalid,perparty_s,batched_s,hybrid_s,batched_fe");
    let mu = 80;
    let r = make_round(mu, 20, 5, 3);
    for m in [0usize, 1, 2, 4, 8, 16, 32] {
        let mut es = r.es.clone();
        for i in 0..m { let j = (i * mu) / m.max(1) + 1; es[j % mu].rho = g1() * rs(); }
        let inv = (0..mu).filter(|i| !audit_one(&es[*i], true)).count();
        assert_eq!(inv, m);
        let t = |b: bool| median((0..3).map(|_| { let s = Instant::now(); assert!(judge_plus_fixed(&es, b).is_none()); s.elapsed().as_secs_f64() }).collect());
        let (pp, bt) = (t(false), t(true));
        let hy = median((0..3).map(|_| { let s = Instant::now(); assert!(judge_plus_hybrid(&es).is_none()); s.elapsed().as_secs_f64() }).collect());
        reset(); judge_plus_fixed(&es, true); let c = counts();
        println!("{m},{:.6},{:.6},{:.6},{}", pp, bt, hy, c.1);
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("security") => security(),
        Some("timing") => timing(),
        Some("counts") => pairing_counts(),
        Some("ksweep") => ksweep(),
        Some("tkgsweep") => tkgsweep(),
        Some("invalid") => invalid_rho(),
        _ => { security(); timing(); }
    }
}
