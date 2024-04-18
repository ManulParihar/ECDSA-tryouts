package com.test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.web3j.crypto.*;
import org.web3j.utils.Numeric;

public class ECKeyManagement {

	static String compressPubKey(BigInteger pubKey) {
		String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
		String pubKeyHex = pubKey.toString(16);
		String pubKeyX = pubKeyHex.substring(0, 64);

		return pubKeyYPrefix + pubKeyX;
	}

    public static String signMessage(String message, ECKeyPair ecKeyPair) {
        byte[] hash = message.getBytes(StandardCharsets.UTF_8);
        Sign.SignatureData signature = Sign.signPrefixedMessage(hash, ecKeyPair);
        String r = Numeric.toHexString(signature.getR());
        String s = Numeric.toHexString(signature.getS()).substring(2);
        String v = Numeric.toHexString(signature.getV()).substring(2);
        System.out.println(r + "    " + s + "    " + v);
        return r + s + v;
    }

	public static void main(String[] args) throws Exception {
        
		// Generate a random private key
        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();

		BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
		ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);
        String address = Keys.getAddress(pubKey);

		System.out.println("Private key (256 bits): " + privKey.toString(16));
		System.out.println("Public key (512 bits): " + pubKey.toString(16));
		System.out.println("Public key (compressed): " + compressPubKey(pubKey));
        System.out.println("Address: " + address);

		// Sign message
		String msg = "TEST";
        String signedMessage = signMessage(msg, keyPair);
        System.out.println("SignedMessage: " + signedMessage);
	}
}
