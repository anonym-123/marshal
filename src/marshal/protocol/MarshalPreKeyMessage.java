package marshal.protocol;

import org.whispersystems.libsignal.ecc.ECPublicKey;

public class MarshalPreKeyMessage {

	MarshalMessage message;
	ECPublicKey senderEphemeralKeyPair;
	ECPublicKey senderIdentityKey;
	ECPublicKey senderMarshalSignatureKey;
	byte[] marshalSignatureKeySignature;
	ECPublicKey initSameUserRatchetKey;
	int receiverSignedPreKeyId;
	int receiverPreKeyId;

	public MarshalPreKeyMessage(MarshalMessage message, ECPublicKey senderEphemeralKeyPair,
			ECPublicKey senderIdentityKey, ECPublicKey senderMarshalSignatureKey,
			byte[] marshalSignatureKeySignature, ECPublicKey initSameUserRatchetKey, int receiverSignedPreKeyId,
			int receiverPreKeyId) {
		this.message = message;
		this.senderEphemeralKeyPair = senderEphemeralKeyPair;
		this.senderIdentityKey = senderIdentityKey;
		this.senderMarshalSignatureKey = senderMarshalSignatureKey;
		this.marshalSignatureKeySignature = marshalSignatureKeySignature;
		this.initSameUserRatchetKey = initSameUserRatchetKey;
		this.receiverSignedPreKeyId = receiverSignedPreKeyId;
		this.receiverPreKeyId = receiverPreKeyId;
	}

	public MarshalMessage getMessage() {
		return message;
	}

	public void setMessage(MarshalMessage message) {
		this.message = message;
	}

	public ECPublicKey getSenderEphemeralKeyPair() {
		return senderEphemeralKeyPair;
	}

	public void setSenderEphemeralKeyPair(ECPublicKey senderEphemeralKeyPair) {
		this.senderEphemeralKeyPair = senderEphemeralKeyPair;
	}

	public ECPublicKey getSenderIdentityKey() {
		return senderIdentityKey;
	}

	public void setSenderIdentityKey(ECPublicKey senderIdentityKey) {
		this.senderIdentityKey = senderIdentityKey;
	}

	public int getReceiverSignedPreKeyId() {
		return receiverSignedPreKeyId;
	}

	public void setReceiverSignedPreKeyId(int receiverSignedPreKeyId) {
		this.receiverSignedPreKeyId = receiverSignedPreKeyId;
	}

	public int getReceiverPreKeyId() {
		return receiverPreKeyId;
	}

	public void setReceiverPreKeyId(int receiverPreKeyId) {
		this.receiverPreKeyId = receiverPreKeyId;
	}

	public ECPublicKey getInitSameUserRatchetKey() {
		return initSameUserRatchetKey;
	}

	public void setInitSameUserRatchetKey(ECPublicKey initRatchetKey) {
		this.initSameUserRatchetKey = initRatchetKey;
	}

	public ECPublicKey getSenderMarshalSignatureKey() {
		return senderMarshalSignatureKey;
	}

	public void setSenderMarshalSignatureKey(ECPublicKey senderMarshalSignatureKey) {
		this.senderMarshalSignatureKey = senderMarshalSignatureKey;
	}

	public byte[] getMarshalSignatureKeySignature() {
		return marshalSignatureKeySignature;
	}

	public void setMarshalSignatureKeySignature(byte[] marshalSignatureKeySignature) {
		this.marshalSignatureKeySignature = marshalSignatureKeySignature;
	}
	
}
