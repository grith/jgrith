package grith.jgrith.utils;

import grith.jgrith.cred.GridCliParameters;

import java.util.List;
import java.util.Set;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterDescription;
import com.beust.jcommander.internal.Lists;
import com.google.common.collect.Sets;

public class CommandlineArgumentHelpers {

	public static String[] extractGridParameters(GridCliParameters params, String[] args) {
		
		List<String> gps = Lists.newLinkedList();
		
		Set<String> bools = booleanParams(params);
		Set<String> nonBools = nonBooleanParameters(params);
		
		boolean skipNext = false;
		String lastNonBool = null;

		
		for (String arg : args) {
			if ( skipNext ) {
				gps.add(arg);
				skipNext = false;
				continue;
			}
			if ( bools.contains(arg) ) {
				gps.add(arg);
			} else if ( nonBools.contains(arg) ) {
				gps.add(arg);
				skipNext = true;
			}
		}
		
		if ( skipNext ) {
			throw new RuntimeException(lastNonBool+" parameter needs value.");
		}
		
		return gps.toArray(new String[]{});
		
	}
	
	public static String[] extractNonGridParameters(GridCliParameters params, String[] args) {
		
		List<String> gps = Lists.newLinkedList();
		
		Set<String> bools = booleanParams(params);
		Set<String> nonBools = nonBooleanParameters(params);
		
		boolean skipNext = false;
		String lastNonBool = null;
		
		for (String arg : args) {
			if ( skipNext ) {
				skipNext = false;
				continue;
			}
			if ( bools.contains(arg) ) {
				continue;
			} else if ( nonBools.contains(arg) ) {
				skipNext = true;
				lastNonBool = arg;
				continue;
			}
			gps.add(arg);
		}
		
		if ( skipNext ) {
			throw new RuntimeException(lastNonBool+" parameter needs value.");
		}
		
		return gps.toArray(new String[]{});
		
	}
	
	public static Set<String> booleanParams(GridCliParameters params) {
		
		Set<String> bools = Sets.newTreeSet();
		
    	JCommander jc = new JCommander(params, new String[]{});
    	
    	List<ParameterDescription> list = jc.getParameters();

    	for ( ParameterDescription pd : list ) {

    		Class type = pd.getField().getType();
    		if ( type == boolean.class || type == Boolean.class ) {
        		String[] tokens = pd.getNames().split(",");
        		for ( String token : tokens ) {
        			bools.add(token.trim());
        		}
    		}
    	}
    	return bools;
		
	}
	
	public static Set<String> nonBooleanParameters(GridCliParameters params) {
		
		Set<String> nonbools = Sets.newTreeSet();
		
    	JCommander jc = new JCommander(params, new String[]{});
    	
    	List<ParameterDescription> list = jc.getParameters();

    	for ( ParameterDescription pd : list ) {

    		Class type = pd.getField().getType();
    		if ( type != boolean.class && type != Boolean.class ) {
        		String[] tokens = pd.getNames().split(",");
        		for ( String token : tokens ) {
        			nonbools.add(token.trim());
        		}
    		}
    	}
    	return nonbools;
	}

}
