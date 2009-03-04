package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Frame;

import javax.swing.JDialog;
import javax.swing.JPanel;

import org.vpac.security.light.plainProxy.LocalProxy;
import org.vpac.security.light.utils.ActionPerformedListener;

public class LocalProxyDialog extends JDialog implements ActionPerformedListener{

	private static final long serialVersionUID = 1L;

	private JPanel jContentPane = null;
	
	public static final int PROXY_INIT_CANCELLED = 0;
	public static final int PROXY_NOT_VALID = -1;

	private int proxyStatus = 0;

	private LocalProxyPanel localProxyPanel = null;

	/**
	 * @param owner
	 */
	public LocalProxyDialog(Frame owner) {
		super(owner, true);
		initialize();
	}
	
	/**
	 * This method initializes this
	 * 
	 * @return void
	 */
	private void initialize() {
		this.setSize(434, 244);
		this.setContentPane(getJContentPane());
	}

	/**
	 * This method initializes jContentPane
	 * 
	 * @return javax.swing.JPanel
	 */
	private JPanel getJContentPane() {
		if (jContentPane == null) {
			jContentPane = new JPanel();
			jContentPane.setLayout(new BorderLayout());
			jContentPane.add(getLocalProxyPanel(), BorderLayout.CENTER);
		}
		return jContentPane;
	}

	/**
	 * This method initializes localProxyPanel	
	 * 	
	 * @return org.vpac.security.light.view.swing.LocalProxyPanel	
	 */
	private LocalProxyPanel getLocalProxyPanel() {
		if (localProxyPanel == null) {
			localProxyPanel = new LocalProxyPanel(this);
		}
		return localProxyPanel;
	}

	public void success(String actionName, boolean success, Object[] params) {
		
		if ( LocalProxyPanel.CANCEL_NAME.equals(actionName) ) {
			// no proxy created...
			this.proxyStatus = PROXY_INIT_CANCELLED;
			this.setVisible(false);
		} else if ( LocalProxyPanel.CREATED_NAME.equals(actionName) ) {
			if ( success ) {
				// proxy created successfully
				try {
					this.proxyStatus = LocalProxy.loadGSSCredential().getRemainingLifetime();
				} catch (Exception e) {
					this.proxyStatus = PROXY_NOT_VALID;
				}
				this.setVisible(false);
			} else {
				// proxy creation not successful
				this.setVisible(false);
			}
		}
		
	}
	
	public static void main(String[] args) {
		LocalProxyDialog lpd = new LocalProxyDialog(null);
		lpd.setVisible(true);
		
		System.out.println("Proxy status: "+lpd.getProxyStatus());
		
		
		
	}
	
	/**
	 * Returns the status of the proxy creation, where -1 means no Valid proxy 0 means the user cancelled the creation process
	 * and everything greater than 0 is the lifetime of the local proxy in seconds.
	 * @return the status of the local proxy
	 */
	public int getProxyStatus() {
		return proxyStatus;
	}

}  //  @jve:decl-index=0:visual-constraint="10,10"
