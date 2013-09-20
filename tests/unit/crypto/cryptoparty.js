(function( $ ) {

module( "PBKDF2 - Password encrytion" );

test( "Password validation with random salt provided", function() {

    var hex = sjcl.codec.hex;
    var salt = new sjcl.prng(12);
    var count = 2048;
    var output;
    rawPassword = sjcl.misc.pbkdf2(PASSWORD, hex.fromBits(salt), count);
    equal( hex.fromBits(rawPassword),  ENCRYPTED_PASSWORD, "Password is not the same" );

});

module( "Symmetric encrytion with GCM" );

test( "Encrypt raw bytes", function() {
    var gcm = sjcl.mode.gcm;
    var hex = sjcl.codec.hex;
    var key = new sjcl.cipher.aes(hex.toBits(BOB_SECRET_KEY));
    
    var IV = hex.toBits(BOB_IV);
    var message = hex.toBits(MESSAGE);
    var aad = hex.toBits(BOB_AAD);
    
    var cipherText = gcm.encrypt(key, message, IV, aad, TAG_SIZE);
    equal( hex.fromBits(cipherText),  CIPHERTEXT, "Encryption has failed" );
});

test( "Decrypt raw bytes", function() {

    var gcm = sjcl.mode.gcm;
    var hex = sjcl.codec.hex;
    var key = new sjcl.cipher.aes(hex.toBits(BOB_SECRET_KEY));
    
    var IV = hex.toBits(BOB_IV);
    var message = hex.toBits(MESSAGE);
    var aad = hex.toBits(BOB_AAD);
    
    var cipherText = gcm.encrypt(key, message, IV, aad, TAG_SIZE);
    var plainText = gcm.decrypt(key, cipherText, IV, aad, TAG_SIZE);
    equal( hex.fromBits(plainText),  MESSAGE, "Encryption has failed" );
});

test( "Decrypt corrupted ciphertext", function() {
    var gcm = sjcl.mode.gcm;
    var hex = sjcl.codec.hex;
    var key = new sjcl.cipher.aes(hex.toBits(BOB_SECRET_KEY));
    
    var IV = hex.toBits(BOB_IV);
    var message = hex.toBits(MESSAGE);
    var aad = hex.toBits(BOB_AAD);
    
    var cipherText = gcm.encrypt(key, message, IV, aad, TAG_SIZE);
    cipherText[23] = ' ';
    
    throws(function(){
        gcm.decrypt(key, cipherText, IV, aad, TAG_SIZE)
    }, "Should throw an exception for corrupted ciphers");
});

test( "Decrypt with corrupted IV", function() {
    var gcm = sjcl.mode.gcm;
    var hex = sjcl.codec.hex;
    var key = new sjcl.cipher.aes(hex.toBits(BOB_SECRET_KEY));
    
    var IV = hex.toBits(BOB_IV);
    var message = hex.toBits(MESSAGE);
    var aad = hex.toBits(BOB_AAD);
    
    var cipherText = gcm.encrypt(key, message, IV, aad, TAG_SIZE);
    IV[23] = ' ';
    throws(function(){
        gcm.decrypt(key, cipherText, IV, aad, TAG_SIZE)
    }, "Should throw an exception for corrupted IVs");
});

module( "TODO - Asymmetric encryption with ECC" );

test( "TODO", function() {
    ok( 1 == "1", "Passed!" );
});

})( jQuery );
