package rsa_module.utility;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;

public class File_Accesser {
	
	private File file;
	
	public File_Accesser(String filename) {
		this(new File(Paths.get(filename).toString()));
	}
	
	public File_Accesser(File file) {
		this.file = file;
	}
	
	public String readFile() {
		try {
			return extract_text_from_file(file);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	private String extract_text_from_file(File file) throws FileNotFoundException, IOException {
		FileReader file_reader = new FileReader(file);
		String text = read_file_into_String(file_reader);
		file_reader.close();
		return text;
	}
	
	private String read_file_into_String(FileReader file_reader) throws IOException {
		StringBuilder text = new StringBuilder();
		int c = file_reader.read();
		while (c != -1) {
			text.append((char) c);
			c = file_reader.read();
		}
		return text.toString();
	}
	
	public void writeToFile(String text) {
		try {
			FileWriter fw = new FileWriter(file);
			fw.write(text);
			fw.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}
}