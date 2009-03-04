package org.vpac.security.light.view.swing;

import java.awt.Component;
import java.awt.Dimension;
import java.util.ResourceBundle;

import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class Utils {
	
	private static ResourceBundle errorMessages = ResourceBundle.getBundle(
			  "MyProxyErrorMessagesBundle", java.util.Locale.getDefault());

	private static ResourceBundle messages = ResourceBundle.getBundle(
			  "MyProxyMessagesBundle", java.util.Locale.getDefault());

	
	
	public static JScrollPane getMessagePane(String message) {
		
		JScrollPane scrollPane = new JScrollPane();
		scrollPane.setPreferredSize(new Dimension(400, 200));
		
		JTextArea pane = new JTextArea(message,0,40);
		pane.setLineWrap(true);
		//pane.setText(message);
		
		scrollPane.setViewportView(pane);
		
		return scrollPane;
	}
	
	public static void showDialog(Component parent, String message) {
		String message_new = null;
		message_new = messages.getString(message+".text")+".";

		JOptionPane.showMessageDialog(parent,
				Utils.getMessagePane(message_new),
			    messages.getString(message+".title"),
			    JOptionPane.INFORMATION_MESSAGE);
	}
	
	public static void showErrorMessage(Component parent, String message, Exception e){
		
		String message_new = null;
		if ( e == null ) {
			message_new = errorMessages.getString(message+".error")+".";
		} else {
			message_new = errorMessages.getString(message+".error")+": "+e.getMessage();
		}
		JOptionPane.showMessageDialog(parent,
				Utils.getMessagePane(message_new),
			    errorMessages.getString(message+".title"),
			    JOptionPane.ERROR_MESSAGE);
		
	}
	
	public static void showErrorMessage(Component parent, String message, String message2, Exception e){
		
		String message_new = null;
		if ( e == null ) {
			message_new = errorMessages.getString(message+".error")+" "+message2+".";
		} else {
			message_new = errorMessages.getString(message+".error")+" "+message2+": "+e.getMessage();
		}
		JOptionPane.showMessageDialog(parent,
				Utils.getMessagePane(message_new),
			    errorMessages.getString(message+".title"),
			    JOptionPane.ERROR_MESSAGE);
		
	}

}
