package marshal.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.whispersystems.libsignal.ecc.ECPublicKey;

public class MarshalMessage {
	
	byte[] ciphertext;
	byte[] iv;
	byte[] ciphertextSignature;
	int countX;
	int countY;
	ECPublicKey senderSameUserRatchetKey;
	byte[] sigma;
	ECPublicKey senderCrossUserRatchetKey;
	byte[] senderListChainRatchetKey;
	
	public MarshalMessage(byte[] ciphertext, byte[] iv, byte[] ciphertextSignature, int countX, int countY, ECPublicKey senderSameUserRatchetKey, byte[] sigma, ECPublicKey senderCrossUserRatchetKey, byte[] senderListChainRatchetKey) {
		this.ciphertext = ciphertext;
		this.iv = iv;
		this.ciphertextSignature = ciphertextSignature;
		this.countX = countX;
		this.countY = countY;
		this.senderSameUserRatchetKey = senderSameUserRatchetKey;
		this.sigma = sigma;
		this.senderCrossUserRatchetKey = senderCrossUserRatchetKey;
		this.senderListChainRatchetKey = senderListChainRatchetKey;
	}

	public byte[] getCiphertext() {
		return ciphertext;
	}

	public void setCiphertext(byte[] ciphertext) {
		this.ciphertext = ciphertext;
	}

	public byte[] getIv() {
		return iv;
	}

	public void setIv(byte[] iv) {
		this.iv = iv;
	}

	public byte[] getCiphertextSignature() {
		return ciphertextSignature;
	}

	public void setCiphertextSignature(byte[] ciphertextSignature) {
		this.ciphertextSignature = ciphertextSignature;
	}

	public int getCountX() {
		return countX;
	}

	public void setCountX(int countX) {
		this.countX = countX;
	}

	public int getCountY() {
		return countY;
	}

	public void setCountY(int countY) {
		this.countY = countY;
	}

	public ECPublicKey getSenderSameUserRatchetKey() {
		return senderSameUserRatchetKey;
	}

	public void setSenderSameUserRatchetKey(ECPublicKey senderSameUserRatchetKey) {
		this.senderSameUserRatchetKey = senderSameUserRatchetKey;
	}

	public byte[] getSigma() {
		return sigma;
	}

	public void setSigma(byte[] sigma) {
		this.sigma = sigma;
	}

	public ECPublicKey getSenderCrossUserRatchetKey() {
		return senderCrossUserRatchetKey;
	}

	public void setSenderCrossUserRatchetKey(ECPublicKey senderCrossUserRatchetKey) {
		this.senderCrossUserRatchetKey = senderCrossUserRatchetKey;
	}

	public byte[] getSenderListChainRatchetKey() {
		return senderListChainRatchetKey;
	}

	public void setSenderListChainRatchetKey(byte[] senderListChainRatchetKey) {
		this.senderListChainRatchetKey = senderListChainRatchetKey;
	}
	
	public byte[] serialize() {
		byte[] result;
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			outputStream.write(this.ciphertext);
			outputStream.write(this.iv);
			outputStream.write(this.ciphertextSignature);
			outputStream.write(this.countX);
			outputStream.write(this.countY);
			outputStream.write(this.senderSameUserRatchetKey.serialize());
			outputStream.write(this.sigma);
			outputStream.write(this.senderCrossUserRatchetKey.serialize());
			outputStream.write(this.senderListChainRatchetKey);
			result = outputStream.toByteArray( );
		} catch (IOException e) {
			throw new AssertionError(e);
		}
		return result;
	}
	
}
