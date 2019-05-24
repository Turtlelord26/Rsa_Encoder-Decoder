package rsaModule;

import java.util.HashMap;

/**
 * An extension of HashMap with designed toString formatting.
 */
public class StringableHashMap<K, V> extends HashMap<K, V> {

	/**
	 * Default serialization constant.
	 */
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
