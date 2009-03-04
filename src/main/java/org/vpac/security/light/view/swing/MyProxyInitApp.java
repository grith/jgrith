package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;

import javax.swing.JFrame;

import org.vpac.security.light.utils.ActionPerformedListener;

public class MyProxyInitApp implements ActionPerformedListener{

	private MyProxyInitPanel myProxyInitPanel;
	private JFrame frame;

	/**
	 * Launch the application
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			MyProxyInitApp window = new MyProxyInitApp();
			window.frame.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Create the application
	 */
	public MyProxyInitApp() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 500, 375);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.getContentPane().add(getMyProxyInitPanel(), BorderLayout.CENTER);
	}
	/**
	 * @return
	 */
	protected MyProxyInitPanel getMyProxyInitPanel() {
		if (myProxyInitPanel == null) {
			myProxyInitPanel = new MyProxyInitPanel(this, "myproxy.arcs.org.au", 443, -1, null, null);
		}
		return myProxyInitPanel;
	}

	public void success(String actionName, boolean success, Object[] params) {

		if ( MyProxyInitPanel.SUCCESS_ACTION_NAME.equals(actionName) ) {
			Utils.showDialog(this.frame, "myProxyUploadedSuccessful");
			//System.exit(0);
		} 
		
	}

}
