package rsa_module.data_structures;

import java.util.HashMap;

public class Stringable_HashMap<K, V> extends HashMap<K, V> {

	private static final long serialVersionUID = 1L;
	
	@Override
	public String toString() {
		StringBuilder printForm = new StringBuilder();
		for (K key : this.keySet()) {
			printForm.append(this.get(key).toString() + System.lineSeparator());
		}
		return printForm.toString();
	}
}
