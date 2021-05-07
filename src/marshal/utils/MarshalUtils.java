package marshal.utils;

import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class MarshalUtils {

	public static void printBytes(byte[] bytes) {
		for (byte b : bytes) {
			String st = String.format("%02X", b);
			System.out.print(st + " ");
		}
		System.out.println("");
	}
	
	public static void writeCSV(List<String> data, String filename) throws IOException {
		FileWriter csvWriter = new FileWriter(filename);
		csvWriter.append("Nb_messages,Execution_time\n");
		for(String line : data)
			csvWriter.append(line);
		csvWriter.flush();
		csvWriter.close();
	}
	
}
