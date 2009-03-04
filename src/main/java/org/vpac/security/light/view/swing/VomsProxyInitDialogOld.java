package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JDialog;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;
import org.vpac.security.light.CredentialHelpers;
import org.vpac.security.light.plainProxy.LocalProxy;
import org.vpac.security.light.vomsProxy.VomsProxy;

public class VomsProxyInitDialogOld extends JDialog implements ProxyInitListener {

	private VomsProxyInitPanelOld vomsProxyInitPanel;
	/**
	 * Launch the application
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			VomsProxyInitDialogOld dialog = new VomsProxyInitDialogOld();
			dialog.addProxyInitListener(dialog);
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

	/**
	 * Create the dialog
	 */
	public VomsProxyInitDialogOld() {
		super();
		setBounds(100, 100, 500, 375);
		getContentPane().add(getVomsProxyInitPanel(), BorderLayout.CENTER);
		//
	}
	/**
	 * @return
	 */
	protected VomsProxyInitPanelOld getVomsProxyInitPanel() {
		if (vomsProxyInitPanel == null) {
			vomsProxyInitPanel = new VomsProxyInitPanelOld();
		}
		return vomsProxyInitPanel;
	}

	public void proxyCreated(GlobusCredential newProxy) {
		
		int type = 0;
		//TODO fix that
		
		if ( type == ProxyInitListener.PLAIN_PROXY_CREATED ) {
			try {
				// you could also use the "newProxy" from the method signature
				System.out.println("Plain proxy created. Valid until: "+LocalProxy.loadGlobusCredential().getTimeLeft()+" seconds.");
			} catch (GlobusCredentialException e) {
				e.printStackTrace();
			}
		} else if ( type == ProxyInitListener.VOMS_PROXY_CREATED ) {
			System.out.println("Voms proxy created. Valid until: "+newProxy.getTimeLeft()+" seconds.");

			try {
				VomsProxy vomsProxy = new VomsProxy(newProxy);
				
				for (String info : vomsProxy.getVomsInfo()) {
					System.out.println(info);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			
		}
		
	}
	
	public void addProxyInitListener(ProxyInitListener listener) {
		getVomsProxyInitPanel().addProxyListener(listener);
	}

	public void removeProxyInitListener(ProxyInitListener listener) {
		getVomsProxyInitPanel().removeProxyListener(listener);
	}

	public void proxyDestroyed() {
		// TODO Auto-generated method stub
		
	}
	
}
