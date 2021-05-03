package marshal.ratchet;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.ecc.Curve;
import org.whispersystems.libsignal.ecc.ECKeyPair;
import org.whispersystems.libsignal.kdf.HKDF;
import org.whispersystems.libsignal.kdf.HKDFv3;

import marshal.protocol.MarshalPreKeyMessage;
import marshal.state.MarshalPreKeyBundle;
import marshal.state.MarshalProtocolStore;
import marshal.state.MarshalSession;

public class MarshalRatchetingSession {

	public static void initializeAliceSession(MarshalProtocolStore store, MarshalSession session, MarshalPreKeyBundle preKeyBundle) throws InvalidKeyException {
		try {

			ECKeyPair initSameUserRatchetKey = Curve.generateKeyPair();
			session.setInitSameUserRatchetKey(initSameUserRatchetKey);

			// X3DH
			ByteArrayOutputStream masterSecret = new ByteArrayOutputStream();
			masterSecret.write(getDiscontinuityBytes());
			masterSecret.write(Curve.calculateAgreement(preKeyBundle.getSignedPreKeyPublic(), store.getIdentityKeyPair().getPrivateKey()));
			masterSecret.write(Curve.calculateAgreement(preKeyBundle.getIdentityKey().getPublicKey(), session.getEphemeralKeyPair().getPrivateKey()));
			masterSecret.write(Curve.calculateAgreement(preKeyBundle.getSignedPreKeyPublic(), session.getEphemeralKeyPair().getPrivateKey()));
			masterSecret.write(Curve.calculateAgreement(preKeyBundle.getPreKeyPublic(), session.getEphemeralKeyPair().getPrivateKey()));
			
			// Asymmetric ratchet
			byte[] dhSecret = Curve.calculateAgreement(preKeyBundle.getSignedPreKeyPublic(), initSameUserRatchetKey.getPrivateKey());
			
			// Derive Chain key from X3DH secret and asymmetric ratchet secret
			byte[] chainKey = calculateDerivedKey(dhSecret, masterSecret.toByteArray());
			session.setChainKey(chainKey);
			
		} catch (IOException e) {
			throw new AssertionError(e);
		}	
	}
	
	public static void initializeBobSession(MarshalProtocolStore store, MarshalSession session, MarshalPreKeyMessage preKeyMessage) throws InvalidKeyException, InvalidKeyIdException  {
		try {
			
			// X3DH
			ByteArrayOutputStream masterSecret = new ByteArrayOutputStream();
			masterSecret.write(getDiscontinuityBytes());
			masterSecret.write(Curve.calculateAgreement(preKeyMessage.getSenderIdentityKey(), store.loadSignedPreKey(preKeyMessage.getReceiverSignedPreKeyId()).getKeyPair().getPrivateKey()));
			masterSecret.write(Curve.calculateAgreement(preKeyMessage.getSenderEphemeralKeyPair(), store.getIdentityKeyPair().getPrivateKey()));
			masterSecret.write(Curve.calculateAgreement(preKeyMessage.getSenderEphemeralKeyPair(), store.loadSignedPreKey(preKeyMessage.getReceiverSignedPreKeyId()).getKeyPair().getPrivateKey()));
			masterSecret.write(Curve.calculateAgreement(preKeyMessage.getSenderEphemeralKeyPair(), store.loadPreKey(preKeyMessage.getReceiverPreKeyId()).getKeyPair().getPrivateKey()));
			
			// Asymmetric Ratchet
			byte[] dhSecret = Curve.calculateAgreement(preKeyMessage.getInitSameUserRatchetKey(), store.loadSignedPreKey(preKeyMessage.getReceiverSignedPreKeyId()).getKeyPair().getPrivateKey());
			
			// Derive Chain key from X3DH secret and asymmetric ratchet secret
			byte[] chainKey = calculateDerivedKey(dhSecret, masterSecret.toByteArray());
			session.setChainKey(chainKey);
	
		} catch (IOException e) {
			throw new AssertionError(e);
		}	
	}

	private static byte[] getDiscontinuityBytes() {
		byte[] discontinuity = new byte[32];
		Arrays.fill(discontinuity, (byte) 0xFF);
		return discontinuity;
	}

	private static byte[] calculateDerivedKey(byte[] masterSecret, byte[] dhSecret) {
	    HKDF     kdf                = new HKDFv3();
	    return kdf.deriveSecrets(dhSecret, masterSecret, 32); 
	}
	
}
