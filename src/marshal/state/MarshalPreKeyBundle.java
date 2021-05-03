package marshal.state;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;

public class MarshalPreKeyBundle {

	private int preKeyId;
	private ECPublicKey preKeyPublic;
	
	private int signedPreKeyId;
	private ECPublicKey signedPreKeyPublic;
	private byte[] signedPreKeySignature;

	private IdentityKey identityKey;
	
	private ECPublicKey initMarshalCrossUserRatchetKeyPair;
	
	public MarshalPreKeyBundle(int preKeyId, ECPublicKey preKeyPublic, int signedPreKeyId,
			ECPublicKey signedPreKeyPublic, byte[] signedPreKeySignature, IdentityKey identityKey, ECPublicKey initMarshalCrossUserRatchetKeyPair) {
		this.preKeyId = preKeyId;
		this.preKeyPublic = preKeyPublic;
		this.signedPreKeyId = signedPreKeyId;
		this.signedPreKeyPublic = signedPreKeyPublic;
		this.signedPreKeySignature = signedPreKeySignature;
		this.identityKey = identityKey;
		this.initMarshalCrossUserRatchetKeyPair = initMarshalCrossUserRatchetKeyPair;
	}

	public int getPreKeyId() {
		return preKeyId;
	}

	public ECPublicKey getPreKeyPublic() {
		return preKeyPublic;
	}

	public int getSignedPreKeyId() {
		return signedPreKeyId;
	}

	public ECPublicKey getSignedPreKeyPublic() {
		return signedPreKeyPublic;
	}

	public byte[] getSignedPreKeySignature() {
		return signedPreKeySignature;
	}

	public IdentityKey getIdentityKey() {
		return identityKey;
	}

	public ECPublicKey getInitMarshalCrossUserRatchetPublicKey() {
		return initMarshalCrossUserRatchetKeyPair;
	}
	
}
