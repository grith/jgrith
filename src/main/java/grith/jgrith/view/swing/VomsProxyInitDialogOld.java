package grith.jgrith.view.swing;

import grith.jgrith.plainProxy.LocalProxy;
import grith.jgrith.vomsProxy.VomsProxy;

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JDialog;

import org.globus.gsi.GlobusCredential;
import org.globus.gsi.GlobusCredentialException;

public class VomsProxyInitDialogOld extends JDialog implements
ProxyInitListener {

	static final Logger myLogger = Logger
			.getLogger(VomsProxyInitDialogOld.class.getName());

	/**
	 * Launch the application
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			VomsProxyInitDialogOld dialog = new VomsProxyInitDialogOld();
			dialog.addProxyInitListener(dialog);
			dialog.addWindowListener(new WindowAdapter() {
				@Override
				public void windowClosing(WindowEvent e) {
					System.exit(0);
				}
			});
			dialog.setVisible(true);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private VomsProxyInitPanelOld vomsProxyInitPanel;

	/**
	 * Create the dialog
	 */
	public VomsProxyInitDialogOld() {
		super();
		setBounds(100, 100, 500, 375);
		getContentPane().add(getVomsProxyInitPanel(), BorderLayout.CENTER);
		//
	}

	public void addProxyInitListener(ProxyInitListener listener) {
		getVomsProxyInitPanel().addProxyListener(listener);
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
		// TODO fix that

		if (type == ProxyInitListener.PLAIN_PROXY_CREATED) {
			try {
				// you could also use the "newProxy" from the method signature
				System.out.println("Plain proxy created. Valid until: "
						+ LocalProxy.loadGlobusCredential().getTimeLeft()
						+ " seconds.");
			} catch (GlobusCredentialException e) {
				myLogger.error(e);
			}
		} else if (type == ProxyInitListener.VOMS_PROXY_CREATED) {
			System.out.println("Voms proxy created. Valid until: "
					+ newProxy.getTimeLeft() + " seconds.");

			try {
				VomsProxy vomsProxy = new VomsProxy(newProxy);

				for (String info : vomsProxy.getVomsInfo()) {
					System.out.println(info);
				}
			} catch (Exception e) {
				myLogger.error(e);
			}

		}

	}

	public void proxyDestroyed() {
		// TODO Auto-generated method stub

	}

	public void removeProxyInitListener(ProxyInitListener listener) {
		getVomsProxyInitPanel().removeProxyListener(listener);
	}

}
