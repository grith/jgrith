package grith.jgrith.view.swing.proxyInit;

import grith.jgrith.voms.VOManagement.VOManager;
import grith.sibboleth.Shibboleth;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JDialog;

import org.globus.common.CoGProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class GenericProxyInitDialog extends JDialog {

	private static final Logger myLogger = LoggerFactory
			.getLogger(GenericProxyInitDialog.class);

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
					GenericProxyInitDialog dialog = new GenericProxyInitDialog(new VOManager());
					dialog.addWindowListener(new WindowAdapter() {
						@Override
						public void windowClosing(WindowEvent e) {
							System.exit(0);
						}
					});
					dialog.setVisible(true);
				} catch (Exception e) {
					myLogger.error(e.getLocalizedMessage());
				}
			}
		});
	}

	private GenericProxyCreationPanel genericProxyInitPanel;
	private final VOManager vom;

	/**
	 * Create the dialog
	 */
	public GenericProxyInitDialog(VOManager vom) {
		super();
		this.vom = vom;
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
			genericProxyInitPanel = new GenericProxyCreationPanel(vom);
		}
		return genericProxyInitPanel;
	}

}
