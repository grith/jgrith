package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;
import java.io.File;

import javax.swing.JFrame;

import org.ietf.jgss.GSSCredential;
import org.vpac.security.light.CredentialHelpers;
import org.vpac.security.light.utils.ActionPerformedListener;

/**
 * This class is not finished. It's just to demonstrate how to use
 * MyProxyGetPanel
 * 
 * @author Markus Binsteiner
 * 
 */
public class MyProxyLogonApp implements ActionPerformedListener {

	/**
	 * Launch the application
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			MyProxyLogonApp window = new MyProxyLogonApp();
			window.frame.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	private MyProxyGetPanel myProxyGetPanel;

	private JFrame frame;

	/**
	 * Create the application
	 */
	public MyProxyLogonApp() {
		initialize();
	}

	/**
	 * @return
	 */
	protected MyProxyGetPanel getMyProxyGetPanel() {
		if (myProxyGetPanel == null) {
			myProxyGetPanel = new MyProxyGetPanel(this, "myproxy.arcs.org.au",
					443, null, -1);
		}
		return myProxyGetPanel;
	}

	/**
	 * Initialize the contents of the frame
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 500, 375);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().add(getMyProxyGetPanel(), BorderLayout.CENTER);
	}

	public void success(String actionName, boolean success, Object[] params) {

		if (MyProxyGetPanel.SUCCESS_ACTION_NAME.equals(actionName)) {
			if (success) {
				GSSCredential cred = (GSSCredential) params[0];
				try {
					CredentialHelpers.writeToDisk(cred, new File("/tmp/proxy"));
					System.exit(0);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		} else if (MyProxyGetPanel.CANCEL_ACTION_NAME.equals(actionName)) {
			System.exit(0);
		}

	}

}
