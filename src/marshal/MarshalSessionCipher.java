package marshal;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.ecc.ECPrivateKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;
import org.whispersystems.libsignal.util.ByteUtil;

import marshal.protocol.MarshalMessage;
import marshal.protocol.MarshalPreKeyMessage;
import marshal.state.MarshalProtocolStore;
import marshal.state.MarshalSession;

public class MarshalSessionCipher {

	private final MarshalProtocolStore store;
	private final SignalProtocolAddress remoteAddress;

	public MarshalSessionCipher(MarshalProtocolStore store, SignalProtocolAddress remoteAddress) {
		this.store = store;
		this.remoteAddress = remoteAddress;
	}

	public MarshalPreKeyMessage encryptPreKeyMessage(byte[] message) throws InvalidKeyException {

		MarshalSession session = this.store.loadSession(remoteAddress);

		ECKeyPair messageSameUserRatchetKey = Curve.generateKeyPair();

		byte[] sigma = getMarshalSignature(session.getRemoteCrossUserRatchetKey(),
				messageSameUserRatchetKey.getPublicKey());
		byte[] messageKey = getMessageKey(sigma, messageSameUserRatchetKey.getPrivateKey(), session.getRemoteIdentityKey().getPublicKey(), session.getChainKey(), session);
		byte[] iv = getIV();
		byte[] additionalData = getAdditionalDataPreKeyMessage(session.getEphemeralKeyPair().getPublicKey(),
															   this.store.getIdentityKeyPair().getPublicKey().getPublicKey(),
															   session.getRemoteIdentityKey().getPublicKey(),
															   session.getRemoteSignedPreKey(),
															   session.getRemotePreKey(),
															   session.getRemoteCrossUserRatchetKey(),
															   session.getInitSameUserRatchetKey().getPublicKey(),
															   session.getLocalCrossUserRatchetKey().getPublicKey(),
															   messageSameUserRatchetKey.getPublicKey(),
															   sigma);
		byte[] ciphertext = getCiphertext(message, messageKey, iv, additionalData);
		byte[] ciphertextSignature = Curve.calculateSignature(this.store.getMarshalSignatureKeyPair().getPrivateKey(), ciphertext);
		
		MarshalMessage marshalMessage = new MarshalMessage(ciphertext, 
														   iv, 
														   ciphertextSignature, 
														   session.getCountX(), 
														   session.getCountY(), 
														   messageSameUserRatchetKey.getPublicKey(), 
														   sigma,
														   session.getLocalCrossUserRatchetKey().getPublicKey());
		MarshalPreKeyMessage marshalPreKeyMessage = new MarshalPreKeyMessage(marshalMessage, 
																			 session.getEphemeralKeyPair().getPublicKey(), 
																			 this.store.getIdentityKeyPair().getPublicKey().getPublicKey(), 
																			 this.store.getMarshalSignatureKeyPair().getPublicKey(), 
																			 this.store.getMarshalSignatureKeySignature(), 
																			 session.getInitSameUserRatchetKey().getPublicKey(), 
																			 session.getRemoteSignedPreKeyId(), 
																			 session.getRemotePreKeyId());
		
		session.setCountX(session.getCountX() + 1);
		
		return marshalPreKeyMessage;

	}
	
	public MarshalPreKeyMessage encryptPreKeyMessageResponse(byte [] message) throws InvalidKeyException {
		
		MarshalSession session = this.store.loadSession(this.remoteAddress);
		
		ECKeyPair messageSameUserRatchetKey = Curve.generateKeyPair();
		ECKeyPair nextCrossUserRatchetKey = Curve.generateKeyPair();
		
		HKDF kdf = new HKDFv3();
		byte[] kdfKey = Curve.calculateAgreement(session.getRemoteCrossUserRatchetKey(), this.store.getIdentityKeyPair().getPrivateKey());
		byte[] kdfData = Curve.calculateAgreement(session.getRemoteIdentityKey().getPublicKey(), session.getLocalCrossUserRatchetKey().getPrivateKey());
		byte[] newChainKey = kdf.deriveSecrets(kdfKey, kdfData, 32);
		
		byte[] sigma = getMarshalSignature(session.getRemoteCrossUserRatchetKey(), messageSameUserRatchetKey.getPublicKey());
		
		byte[] messageKey = getMessageKey(sigma, messageSameUserRatchetKey.getPrivateKey(), session.getRemoteIdentityKey().getPublicKey(), newChainKey, session);
		byte[] iv = getIV();
		byte[] additionalData = getAdditionalDataMessage(nextCrossUserRatchetKey.getPublicKey(), "(1,2)", messageSameUserRatchetKey.getPublicKey(), sigma);
		
		byte[] ciphertext = getCiphertext(message, messageKey, iv, additionalData);
		byte[] ciphertextSignature = Curve.calculateSignature(this.store.getMarshalSignatureKeyPair().getPrivateKey(), ciphertext);
		
		session.setCountY(session.getCountY() + 1);
		
		MarshalMessage marshalMessage = new MarshalMessage (ciphertext,
													iv,
													ciphertextSignature,
													session.getCountX(),
													session.getCountY(),
													messageSameUserRatchetKey.getPublicKey(),
													sigma,
													nextCrossUserRatchetKey.getPublicKey());
		
		MarshalPreKeyMessage marshalPreKeyMessage = new MarshalPreKeyMessage(marshalMessage, null, null, this.store.getMarshalSignatureKeyPair().getPublicKey(), this.store.getMarshalSignatureKeySignature(), null, 0, 0);
		
		session.setCountX(1);
		session.setLocalCrossUserRatchetKey(nextCrossUserRatchetKey);
		
		return marshalPreKeyMessage;
		
	}
	
	public MarshalMessage encrypt(byte[] message, boolean isNewChain) throws InvalidKeyException {
		
		MarshalSession session = this.store.loadSession(this.remoteAddress);
		
		ECKeyPair messageSameUserRatchetKey = Curve.generateKeyPair();
		ECKeyPair crossUserRatchetKey;
		byte[] chainKey;
		if(isNewChain) {
			crossUserRatchetKey = Curve.generateKeyPair();
			HKDF kdf = new HKDFv3();
			byte[] kdfKey = Curve.calculateAgreement(session.getRemoteCrossUserRatchetKey(), this.store.getIdentityKeyPair().getPrivateKey());
			byte[] kdfData = Curve.calculateAgreement(session.getRemoteIdentityKey().getPublicKey(), session.getLocalCrossUserRatchetKey().getPrivateKey());
			chainKey = kdf.deriveSecrets(kdfKey, kdfData, 32);
			session.setCountY(session.getCountY() + 1);
			session.setCountX(1);
		} else {
			crossUserRatchetKey = session.getLocalCrossUserRatchetKey();
			chainKey = session.getChainKey();
			session.setCountX(session.getCountX() + 1);
		}
		
		byte sigma[] = getMarshalSignature(session.getRemoteCrossUserRatchetKey(), messageSameUserRatchetKey.getPublicKey());
		byte[] messageKey = getMessageKey(sigma, messageSameUserRatchetKey.getPrivateKey(), session.getRemoteIdentityKey().getPublicKey(), chainKey, session);
		byte[] iv = getIV();
		String counter = "(" + session.getCountX() + "," + session.getCountY() + ")";
		byte[] additionalData = getAdditionalDataMessage(crossUserRatchetKey.getPublicKey(), counter, messageSameUserRatchetKey.getPublicKey(), sigma);
		
		byte[] ciphertext = getCiphertext(message, messageKey, iv, additionalData);
		byte[] ciphertextSignature = Curve.calculateSignature(this.store.getMarshalSignatureKeyPair().getPrivateKey(), ciphertext);
		
		MarshalMessage marshalMessage = new MarshalMessage (ciphertext,
															iv,
															ciphertextSignature,
															session.getCountX(),
															session.getCountY(),
															messageSameUserRatchetKey.getPublicKey(),
															sigma,
															crossUserRatchetKey.getPublicKey());
		
		if(isNewChain) {
			session.setLocalCrossUserRatchetKey(crossUserRatchetKey);
		}
		
		return marshalMessage;
		
	}
	
	public byte[] decryptPreKeyMessageResponse(MarshalPreKeyMessage preKeyMessage) throws InvalidKeyException, SignatureException {
		
		MarshalSession session = this.store.loadSession(remoteAddress);
		session.setRemoteMarshalSignatureKey(preKeyMessage.getSenderMarshalSignatureKey());
		
		if(!Curve.verifySignature(session.getRemoteMarshalSignatureKey(), preKeyMessage.getMessage().getCiphertext(), preKeyMessage.getMessage().getCiphertextSignature())) {
			throw new SignatureException("Invalide message signature");
		}
		
		byte[] sigma = preKeyMessage.getMessage().getSigma();
		
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(session.getLocalCrossUserRatchetKey().getPublicKey().serialize());
			outputStream.write(preKeyMessage.getMessage().getSenderSameUserRatchetKey().serialize());
			if(!Curve.verifySignature(session.getRemoteMarshalSignatureKey(), outputStream.toByteArray(), sigma)) {
				throw new SignatureException("Invalid signature sigma");
			}
		} catch (IOException e) {
			throw new AssertionError(e);
		}
		
		HKDF kdf = new HKDFv3();
		byte[] kdfKey = Curve.calculateAgreement(session.getRemoteIdentityKey().getPublicKey(), session.getLocalCrossUserRatchetKey().getPrivateKey());
		byte[] kdfData = Curve.calculateAgreement(session.getRemoteCrossUserRatchetKey(), this.store.getIdentityKeyPair().getPrivateKey());
		byte[] newChainKey = kdf.deriveSecrets(kdfKey, kdfData, 32);
		
		byte[] messageKey = getMessageKey(sigma, this.store.getIdentityKeyPair().getPrivateKey(), preKeyMessage.getMessage().getSenderSameUserRatchetKey(), newChainKey, session);
		byte[] iv = preKeyMessage.getMessage().getIv();
		byte[] additionalData = getAdditionalDataMessage(preKeyMessage.getMessage().getSenderCrossUserRatchetKey(), "(1,2)", preKeyMessage.getMessage().getSenderSameUserRatchetKey(), sigma);
		
		byte[] plaintext = getPlaintext(preKeyMessage.getMessage().getCiphertext(), messageKey, iv, additionalData);
		
		session.setRemoteCrossUserRatchetKey(preKeyMessage.getMessage().getSenderCrossUserRatchetKey());
		session.setCountY(session.getCountY() + 1);
		session.setCountX(1);
		
		return plaintext;
		
	}
	
	public byte[] decryptPreKeyMessage(MarshalPreKeyMessage preKeyMessage) throws InvalidKeyException, InvalidKeyIdException, SignatureException {
		
		MarshalSession session = this.store.loadSession(remoteAddress);
		
		// Verify message signature
		if(!Curve.verifySignature(session.getRemoteMarshalSignatureKey(), preKeyMessage.getMessage().getCiphertext(), preKeyMessage.getMessage().getCiphertextSignature())) {
			throw new SignatureException("Invalide message signature");
		}
		
		byte[] sigma = preKeyMessage.getMessage().getSigma();	
		
		// Verify sigma
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(session.getLocalCrossUserRatchetKey().getPublicKey().serialize());
			outputStream.write(preKeyMessage.getMessage().getSenderSameUserRatchetKey().serialize());
			if(!Curve.verifySignature(session.getRemoteMarshalSignatureKey(), outputStream.toByteArray(), sigma)) {
				throw new SignatureException("Invalid signature sigma");
			}
		} catch (IOException e) {
			throw new AssertionError(e);
		}
		
		byte[] messageKey = getMessageKey(sigma, this.store.getIdentityKeyPair().getPrivateKey(), preKeyMessage.getMessage().getSenderSameUserRatchetKey(), session.getChainKey(), session);
		byte[] iv = preKeyMessage.getMessage().getIv();
		byte[] additionalData = getAdditionalDataPreKeyMessage(preKeyMessage.getSenderEphemeralKeyPair(),
															   session.getRemoteIdentityKey().getPublicKey(),
															   this.store.getIdentityKeyPair().getPublicKey().getPublicKey(),
															   this.store.loadSignedPreKey(preKeyMessage.getReceiverSignedPreKeyId()).getKeyPair().getPublicKey(),
															   this.store.loadPreKey(preKeyMessage.getReceiverPreKeyId()).getKeyPair().getPublicKey(), 
															   this.store.getInitMarshalCrossUserRatchetKeyPair().getPublicKey(), 
															   preKeyMessage.getInitSameUserRatchetKey(), 
															   preKeyMessage.getMessage().getSenderCrossUserRatchetKey(),
															   preKeyMessage.getMessage().getSenderSameUserRatchetKey(),
															   sigma);
		
		byte[] plaintext = getPlaintext(preKeyMessage.getMessage().getCiphertext(), messageKey, iv, additionalData);
		
		session.setCountX(session.getCountX() + 1);
		
		return plaintext;
		
	}

	public byte[] decrypt(MarshalMessage message, boolean isNewChain) throws SignatureException, InvalidKeyException {
		
		MarshalSession session = this.store.loadSession(remoteAddress);
		
		// Verify message signature
		if(!Curve.verifySignature(session.getRemoteMarshalSignatureKey(), message.getCiphertext(), message.getCiphertextSignature())) {
			throw new SignatureException("Invalide message signature");
		}
		
		byte[] sigma = message.getSigma();	
		
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(session.getLocalCrossUserRatchetKey().getPublicKey().serialize());
			outputStream.write(message.getSenderSameUserRatchetKey().serialize());
			if(!Curve.verifySignature(session.getRemoteMarshalSignatureKey(), outputStream.toByteArray(), sigma)) {
				throw new SignatureException("Invalid signature sigma");
			}
		} catch (IOException e) {
			throw new AssertionError(e);
		}
		
		byte[] chainKey;
		if(isNewChain) {
			HKDF kdf = new HKDFv3();
			byte[] kdfKey = Curve.calculateAgreement(session.getRemoteIdentityKey().getPublicKey(), session.getLocalCrossUserRatchetKey().getPrivateKey());
			byte[] kdfData = Curve.calculateAgreement(session.getRemoteCrossUserRatchetKey(), this.store.getIdentityKeyPair().getPrivateKey());
			chainKey = kdf.deriveSecrets(kdfKey, kdfData, 32);
			session.setCountY(session.getCountY() + 1);
			session.setCountX(1);
		} else {
			chainKey = session.getChainKey();
			session.setCountX(session.getCountX() + 1);
		}
		
		byte[] messageKey = getMessageKey(sigma, this.store.getIdentityKeyPair().getPrivateKey(), message.getSenderSameUserRatchetKey(), chainKey, session);
		byte[] iv = message.getIv();
		String counter = "(" + session.getCountX() + "," + session.getCountY() + ")";
		byte[] additionalData = getAdditionalDataMessage(message.getSenderCrossUserRatchetKey(), counter, message.getSenderSameUserRatchetKey(), sigma);
		
		byte[] plaintext = getPlaintext(message.getCiphertext(), messageKey, iv, additionalData);
		
		if(isNewChain)
			session.setRemoteCrossUserRatchetKey(message.getSenderCrossUserRatchetKey());
		
		return plaintext;
	}
	
	private byte[] getMarshalSignature(ECPublicKey crossUserRatchetKey, ECPublicKey messageSameUserRatchetKey)
			throws InvalidKeyException {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(crossUserRatchetKey.serialize());
			outputStream.write(messageSameUserRatchetKey.serialize());
			return Curve.calculateSignature(this.store.getMarshalSignatureKeyPair().getPrivateKey(),
					outputStream.toByteArray());
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private byte[] getMessageKey(byte[] sigma, ECPrivateKey privateDhKey, ECPublicKey publicDhKey, byte[] chainKey, MarshalSession session)
			throws InvalidKeyException {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(sigma);
			outputStream.write(Curve.calculateAgreement(publicDhKey,
					privateDhKey));
			HKDF kdf = new HKDFv3();
			byte[] secret = kdf.deriveSecrets(chainKey, outputStream.toByteArray(), 48);
			byte[][] derivedSecret = ByteUtil.split(secret, 32, 16);
			session.setChainKey(derivedSecret[0]);
			return derivedSecret[1];
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private byte[] getIV() {
		SecureRandom random = new SecureRandom();
		byte[] iv = new byte[12];
		random.nextBytes(iv);
		return iv;
	}
	
	private byte[] getAdditionalDataPreKeyMessage(ECPublicKey ek_a, ECPublicKey ik_a, ECPublicKey ik_b, ECPublicKey spk_b, ECPublicKey opk_b, ECPublicKey T0, ECPublicKey Rchpk_0_1, ECPublicKey T1, ECPublicKey Rchpk_1_1, byte[] sigma) {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(ek_a.serialize());
			outputStream.write(ik_a.serialize());
			outputStream.write(ik_b.serialize());
			outputStream.write(spk_b.serialize());
			outputStream.write(opk_b.serialize());
			outputStream.write(T0.serialize());
			outputStream.write(Rchpk_0_1.serialize());
			outputStream.write(T1.serialize());
			outputStream.write("(1,1)".getBytes());
			outputStream.write(Rchpk_1_1.serialize());
			outputStream.write(sigma);
			return outputStream.toByteArray();
		} catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	private byte[] getAdditionalDataMessage(ECPublicKey crossUserRatchetKey, String counter, ECPublicKey messageSameUserRatchetKey, byte[] sigma) {
		try {
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
			outputStream.write(crossUserRatchetKey.serialize());
			outputStream.write(counter.getBytes());
			outputStream.write(messageSameUserRatchetKey.serialize());
			outputStream.write(sigma);
			return outputStream.toByteArray();
		} catch(IOException e) {
			throw new AssertionError(e);
		}
	}
	
	private byte[] getCiphertext(byte[] message, byte[] messageKey, byte[] iv, byte[] additionalData) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec gcmParamSpec = new GCMParameterSpec(16 * 8, iv);
			SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParamSpec);
			cipher.updateAAD(additionalData);
			return cipher.doFinal(message);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new AssertionError(e);
		}
	}

	private byte[] getPlaintext(byte[] ciphertext, byte[] messageKey, byte[] iv, byte[] additionalData) {
		try {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			GCMParameterSpec gcmParamSpec = new GCMParameterSpec(16 * 8, iv);
			SecretKeySpec keySpec = new SecretKeySpec(messageKey, "AES");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParamSpec);
			cipher.updateAAD(additionalData);
			return cipher.doFinal(ciphertext);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new AssertionError(e);
		}
	}

}
