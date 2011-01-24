package grith.jgrith.view.swing.proxyInit;

import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingConstants;

import org.globus.gsi.GlobusCredential;

import au.org.arcs.commonInterfaces.ProxyCreatorHolder;

public class MultiProxyCreationPanel extends JPanel implements
		ProxyCreatorHolder {
	private JTabbedPane tabbedPane;
	private SlcsPanel slcsPanel;
	private LocalX509CertProxyCreatorPanel localX509CertProxyCreatorPanel;
	private MyProxyProxyCreatorPanel myProxyProxyCreatorPanel;
	private final ProxyCreatorHolder holder;

	public MultiProxyCreationPanel(ProxyCreatorHolder holder) {
		this.holder = holder;
		setLayout(new BorderLayout(0, 0));
		add(getTabbedPane(), BorderLayout.CENTER);
	}

	private LocalX509CertProxyCreatorPanel getLocalX509CertProxyCreatorPanel() {
		if (localX509CertProxyCreatorPanel == null) {
			localX509CertProxyCreatorPanel = new LocalX509CertProxyCreatorPanel();
			localX509CertProxyCreatorPanel.setProxyCreatorHolder(this);
		}
		return localX509CertProxyCreatorPanel;
	}

	private MyProxyProxyCreatorPanel getMyProxyProxyCreatorPanel() {
		if (myProxyProxyCreatorPanel == null) {
			myProxyProxyCreatorPanel = new MyProxyProxyCreatorPanel();
			myProxyProxyCreatorPanel.setProxyCreatorHolder(this);
		}
		return myProxyProxyCreatorPanel;
	}

	private SlcsPanel getSlcsPanel() {
		if (slcsPanel == null) {
			slcsPanel = new SlcsPanel((String) null);
			slcsPanel.setProxyCreatorHolder(this);
		}
		return slcsPanel;
	}

	private JTabbedPane getTabbedPane() {
		if (tabbedPane == null) {
			tabbedPane = new JTabbedPane(SwingConstants.TOP);
			tabbedPane.addTab("Institution login", null, getSlcsPanel(), null);
			tabbedPane.addTab("Certificate login", null,
					getLocalX509CertProxyCreatorPanel(), null);
			tabbedPane.addTab("MyProxy Login", null,
					getMyProxyProxyCreatorPanel(), null);
		}
		return tabbedPane;
	}

	public void proxyCreated(GlobusCredential proxy) {

		this.holder.proxyCreated(proxy);
	}

	public void proxyCreationFailed(String message) {

		this.holder.proxyCreationFailed(message);
	}
}
