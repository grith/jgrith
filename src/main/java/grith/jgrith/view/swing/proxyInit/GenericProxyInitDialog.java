package grith.jgrith.view.swing.proxyInit;

import grith.sibboleth.Shibboleth;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JDialog;

import org.apache.log4j.Logger;
import org.globus.common.CoGProperties;


public class GenericProxyInitDialog extends JDialog {

	private static final Logger myLogger = Logger
			.getLogger(GenericProxyInitDialog.class.getName());

	/**
	 * Launch the application
	 * 
	 * @param args
	 */
	public static void main(String args[]) {

		CoGProperties.getDefault().setProperty(
				CoGProperties.ENFORCE_SIGNING_POLICY, "false");
		try {
			Shibboleth.initDefaultSecurityProvider();
		} catch (Exception e) {
			System.err.println("Shib classes not found..");
		}

		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					GenericProxyInitDialog dialog = new GenericProxyInitDialog();
					dialog.addWindowListener(new WindowAdapter() {
						@Override
						public void windowClosing(WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					myLogger.error(e);
				}
			}
		});
	}

	private GenericProxyCreationPanel genericProxyInitPanel;

	/**
	 * Create the dialog
	 */
	public GenericProxyInitDialog() {
		super();
		setBounds(100, 100, 563, 650);
		getContentPane().add(getGenericProxyCreationPanel(),
				BorderLayout.CENTER);
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
