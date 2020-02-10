package rsa_module;

public abstract class Rsa_Encryption_Operator {
	
	protected int length_of_numeric_characters = 4;
	
	protected String[] break_text_into_units(String text, int lengthOfUnits) {
		int textLength = text.length();
		String[] units = new String[determine_number_of_units(text, lengthOfUnits)];
		for (int index = 0; index < units.length; index ++) {
			units[index] = text.substring(index * lengthOfUnits, Math.min((index + 1) * lengthOfUnits, textLength));
		}
		return units;
	}
	
	protected int determine_number_of_units(String text, int lengthOfUnits) {
		int numberOfUnits = text.length() / lengthOfUnits;
		if (text.length() % lengthOfUnits > 0) {
			numberOfUnits++;
		}
		return numberOfUnits;
	}
	
	protected String[] fill_out_units_to_constant_length(String[] units, int unitLength) {
		for (int index = 0; index < units.length; index++) {
			while (units[index].length() < unitLength) {
				units[index] = "0" + units[index];
			}
		}
		return units;
	}
	
	protected String concatenate_units_into_text(String[] units) {
		StringBuilder concatenator = new StringBuilder();
		for (int index = 0; index < units.length; index++) {
			concatenator.append(units[index]);
		}
		return concatenator.toString();
	}
}
