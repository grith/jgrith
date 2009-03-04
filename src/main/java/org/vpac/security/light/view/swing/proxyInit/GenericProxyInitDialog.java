package org.vpac.security.light.view.swing.proxyInit;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JDialog;

import org.apache.log4j.Logger;
import org.globus.gsi.GlobusCredential;
import org.vpac.security.light.view.swing.ProxyInitListener;

import au.org.arcs.commonInterfaces.ProxyCreatorHolder;

public class GenericProxyInitDialog extends JDialog {
	

	private GenericProxyCreationPanel genericProxyInitPanel;
	
	/**
	 * Launch the application
	 * @param args
	 */
	public static void main(String args[]) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GenericProxyInitDialog dialog = new GenericProxyInitDialog();
					dialog.addWindowListener(new WindowAdapter() {
						public void windowClosing(WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the dialog
	 */
	public GenericProxyInitDialog() {
		super();
		setBounds(100, 100, 495, 575);
		getContentPane().add(getGenericProxyCreationPanel(), BorderLayout.CENTER);
		//
	}
	/**
	 * @return
	 */
	protected GenericProxyCreationPanel getGenericProxyCreationPanel() {
		if (genericProxyInitPanel == null) {
			genericProxyInitPanel = new GenericProxyCreationPanel();
		}
		return genericProxyInitPanel;
	}
	
	
	


}
