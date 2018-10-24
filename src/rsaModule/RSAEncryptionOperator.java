package rsaModule;

public abstract class RSAEncryptionOperator {
	
	protected int lengthOfNumericCharacters = 4;
	
	protected String[] breakTextIntoUnits(String text, int lengthOfUnits) {
		int textLength = text.length();
		String[] units = new String[determineNumberOfUnits(text, lengthOfUnits)];
		for (int index = 0; index < units.length; index ++) {
			units[index] = text.substring(index * lengthOfUnits, Math.min((index + 1) * lengthOfUnits, textLength));
		}
		return units;
	}
	
	protected int determineNumberOfUnits(String text, int lengthOfUnits) {
		int numberOfUnits = text.length() / lengthOfUnits;
		if (text.length() % lengthOfUnits > 0) {
			numberOfUnits++;
		}
		return numberOfUnits;
	}
	
	protected String[] fillOutUnitsToConstantLength(String[] units, int unitLength) {
		for (int index = 0; index < units.length; index++) {
			while (units[index].length() < unitLength) {
				units[index] = "0" + units[index];
			}
		}
		return units;
	}
	
	protected String concatenateUnitsIntoText(String[] units) {
		StringBuilder concatenator = new StringBuilder();
		for (int index = 0; index < units.length; index++) {
			concatenator.append(units[index]);
		}
		return concatenator.toString();
	}
}
