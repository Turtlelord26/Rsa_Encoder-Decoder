package rsaModule;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Paths;

/**
 * A class that encapsulates read/write file functions.
 * @author James
 */
public class FileRW {
	
	/**
	 * Stored File object that a FileRW object references for read/write operations.
	 */
	private File file;
	
	/**
	 * Primary constructor takes a file path and converts it to a File object, which is stored.
	 * @param filename The filepath of the file that will be read from or written to.
	 */
	public FileRW(String filename) {
		this.file = new File(Paths.get(filename).toString());
	}
	
	/**
	 * Auxiliary constructor takes a prebuilt File object and stores it.
	 * @param file The file that will be read from or written to.
	 */
	public FileRW(File file) {
		this.file = file;
	}
	
	/**
	 * Method to read and return the contents of the stored file.
	 * @return A String containing the entire contents of the file.
	 */
	public String readFile() {
		try {
			FileReader fr = new FileReader(file);
			try {
				StringBuilder text = new StringBuilder();
				int c = fr.read();
				while (c != -1) {
					text.append((char) c);
					c = fr.read();
				}
				fr.close();
				return text.toString();
			} catch (IOException ioe) {
				// TODO Auto-generated catch block
				ioe.printStackTrace();
			}
		} catch (FileNotFoundException fnfe) {
			// TODO Auto-generated catch block
			fnfe.printStackTrace();
		}
		return null;
	}
	
	/**
	 * Method to write an input String to the stored file.
	 * @param text The text to write to the file.
	 */
	public void writeToFile(String text) {
		try {
			FileWriter fw = new FileWriter(file);
			fw.write(text);
			fw.close();
		} catch (IOException ioe) {
			// TODO Auto-generated catch block
			ioe.printStackTrace();
		}
	}
}
