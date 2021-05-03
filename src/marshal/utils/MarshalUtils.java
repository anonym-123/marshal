package marshal.utils;

public class MarshalUtils {

	public static void printBytes(byte[] bytes) {
		for (byte b : bytes) {
			String st = String.format("%02X", b);
			System.out.print(st + " ");
		}
		System.out.println("");
	}
	
}
