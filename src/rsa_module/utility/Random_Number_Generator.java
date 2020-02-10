package rsa_module.utility;

import java.util.Random;

public class Random_Number_Generator {

	public static double generate_random_double() {
		return generate_random_double(0, 1);
	}
	
	public static double generate_random_double(double scale) {
		return generate_random_double(0, scale);
	}
	
	public static double generate_random_double(double minimum, double maximum) {
		double range = maximum - minimum;
		return minimum + range * Math.random();
	}
	
	public static int generate_random_int(int minimum, int maximum) {
		return (int) generate_random_double((double) minimum, (double) maximum);
	}
	
	public static Random generate_new_random_generator() {
		return new Random();
	}

}
