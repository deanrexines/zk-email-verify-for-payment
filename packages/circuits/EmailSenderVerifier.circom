pragma circom 2.1.5;

include "./email-verifier.circom";
include "./GmailSenderVerifier.circom";
include "./GmailHelloWorldInBodyVerifier.circom";
include "./from_addr_regex.circom";

template EmailSenderVerifier(max_header_bytes, max_body_bytes, n, k, pack_size) {
    var max_email_from_len = 30;
    var max_email_from_packed_bytes = count_packed(max_email_from_len, pack_size);

    signal input in_padded[max_header_bytes];
    signal input pubkey[k];
    signal input signature[k];
    signal input in_len_padded_bytes;
    signal input address;
    signal input body_hash_idx;
    signal input precomputed_sha[32];
    signal input in_body_padded[max_body_bytes];
    signal input in_body_len_padded_bytes;

    signal output pubkey_hash;
    signal output reveal_email_packed[max_email_from_packed_bytes];

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

    // EXTRACT SENDER FROM HEADER
    assert(max_email_from_packed_bytes < max_header_bytes);

    signal input email_from_idx;
    signal output reveal_email_from_packed[max_email_from_packed_bytes];
    signal output sender_email_addr_from_packed[max_email_from_packed_bytes];

    signal (from_regex_out, from_regex_reveal[max_header_bytes]) <== FromAddrRegex(max_header_bytes)(in_padded);
    from_regex_out === 1;
    reveal_email_from_packed <== ShiftAndPackMaskedStr(max_header_bytes, max_email_from_len, pack_size)(from_regex_reveal, email_from_idx);


    // TARGET GMAIL SENDER REGEX: 328,044 constraints
    signal (email_sender_out, sender_email_addr_from_packed[max_body_bytes]) <== GmailSenderVerifier(reveal_email_from_packed)(in_body_padded);
    signal is_sender_email_found <== IsZero()(email_sender_out);
    is_sender_email_found === 0;

    sender_email_addr_from_packed <== ShiftAndPackMaskedStr(max_body_bytes, max_email_from_len, pack_size)(email_sender_out, email_idx);


    #BODY
    // EXTRACT EMAIL BODY
    var max_email_body_len = 21;
    var max_email_body_packed_bytes = count_packed(max_email_body_len, pack_size);
    signal input email_idx;
    signal output reveal_email_body_packed[max_email_body_packed_bytes];

    signal (email_regex_out, email_regex_reveal[max_body_bytes]) <== GmailHelloWorldInBodyVerifier(max_body_bytes)(in_body_padded);
    signal is_hello_world_found_email_body <== IsZero()(email_regex_out);
    is_hello_world_found_email_body === 0;

    reveal_email_packed <== ShiftAndPackMaskedStr(max_body_bytes, max_email_from_len, pack_size)(email_regex_reveal, email_idx);
}
component main { public [ address ] } = EmailSenderVerifier(1024, 1536, 121, 17, 31);