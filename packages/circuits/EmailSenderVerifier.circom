pragma circom 2.1.5;

include "./email-verifier.circom";
include "./gmail_sender_regex.circom";

template EmailSenderVerifier(max_header_bytes, max_body_bytes, n, k, pack_size) {
    signal input in_padded[max_header_bytes];
    signal input pubkey[k];
    signal input signature[k];
    signal input in_len_padded_bytes;
    signal input address;
    signal input body_hash_idx;
    signal input precomputed_sha[32];
    signal input in_body_padded[max_body_bytes];
    signal input in_body_len_padded_bytes;

    signal input email_idx;

    signal output pubkey_hash;
    signal output reveal_email_packed[max_email_packed_bytes];

    component EV = EmailVerifier(max_header_bytes, max_body_bytes, n, k, 0);
    EV.in_padded <== in_padded;
    EV.pubkey <== pubkey;
    EV.signature <== signature;
    EV.in_len_padded_bytes <== in_len_padded_bytes;
    EV.body_hash_idx <== body_hash_idx;
    EV.precomputed_sha <== precomputed_sha;
    EV.in_body_padded <== in_body_padded;
    EV.in_body_len_padded_bytes <== in_body_len_padded_bytes;
    pubkey_hash <== EV.pubkey_hash;

    var max_email_len = 21;
    var max_email_packed_bytes = count_packed(max_email_len, pack_size);

    signal (email_regex_out, email_regex_reveal[max_body_bytes]) <== GmailSenderRegex(max_body_bytes)(in_body_padded);
    signal is_found_email <== IsZero()(email_regex_out);
    is_found_email === 0;

    reveal_email_packed <== ShiftAndPackMaskedStr(max_body_bytes, max_email_len, pack_size)(email_regex_reveal, email_username_idx);
}
component main {public [in_padded, pubkey, signature, in_len_padded_bytes, address, body_hash_idx, precomputed_sha, in_body_padded, in_body_len_padded_bytes, email_idx]}=EmailVerifier(max_header_bytes, max_body_bytes, n, k, 0);
