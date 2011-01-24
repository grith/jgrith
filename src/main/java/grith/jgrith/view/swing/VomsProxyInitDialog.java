package grith.jgrith.view.swing;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;

import com.jgoodies.forms.factories.FormFactory;
import com.jgoodies.forms.layout.CellConstraints;
import com.jgoodies.forms.layout.ColumnSpec;
import com.jgoodies.forms.layout.FormLayout;
import com.jgoodies.forms.layout.RowSpec;

public class VomsProxyInitDialog extends JDialog {

	/**
	 * Launch the application
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		try {
			VomsProxyInitDialog dialog = new VomsProxyInitDialog();
			dialog.setModal(true);
			dialog.setLifetimeDefaults(new Integer[] { 1, 2, 7 });
			dialog.enableWriteToDisk(true);
			// dialog.addProxyListener(proxyListener);
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

	private JButton closeButton;
	private JPanel panel;

	private VomsProxyInfoAndInitPanel vomsProxyInfoAndInitPanel;

	/**
	 * Create the dialog
	 */
	public VomsProxyInitDialog() {
		super();
		setBounds(100, 100, 470, 335);
		getContentPane().add(getPanel(), BorderLayout.CENTER);
		//
		getVomsProxyInfoAndInitPanel().loadPossibleLocalProxy();
	}

	/**
	 * Adds a proxy listener. A proxy listener gets notified whenever the user
	 * creates a new plain/voms proxy.
	 * 
	 * @param l
	 *            the listener
	 */
	public void addProxyListener(ProxyInitListener l) {
		getVomsProxyInfoAndInitPanel().addProxyListener(l);
	}

	/**
	 * If you call this method with true, every proxy that is created with the
	 * panel is stored to the default globus location.
	 * 
	 * It probably makes sense to leave that (false) and manage the writing of
	 * the proxy on your own.
	 * 
	 * @param write
	 *            whether to write a created proxy to disk (true) or not (false
	 *            -- default)
	 */
	public void enableWriteToDisk(boolean write) {
		getVomsProxyInfoAndInitPanel().enableWriteToDisk(write);
	}

	/**
	 * @return
	 */
	protected JButton getCloseButton() {
		if (closeButton == null) {
			closeButton = new JButton();
			closeButton.addActionListener(new ActionListener() {
				public void actionPerformed(final ActionEvent e) {
					VomsProxyInitDialog.this.setVisible(false);
				}
			});
			closeButton.setText("Close");
		}
		return closeButton;
	}

	/**
	 * @return
	 */
	protected JPanel getPanel() {
		if (panel == null) {
			panel = new JPanel();
			panel.setLayout(new FormLayout(new ColumnSpec[] {
					FormFactory.RELATED_GAP_COLSPEC,
					new ColumnSpec("default:grow(1.0)"),
					FormFactory.RELATED_GAP_COLSPEC }, new RowSpec[] {
					FormFactory.DEFAULT_ROWSPEC,
					FormFactory.RELATED_GAP_ROWSPEC,
					FormFactory.DEFAULT_ROWSPEC,
					FormFactory.RELATED_GAP_ROWSPEC }));
			panel.add(getVomsProxyInfoAndInitPanel(), new CellConstraints(2, 1));
			panel.add(getCloseButton(), new CellConstraints(2, 3,
					CellConstraints.RIGHT, CellConstraints.BOTTOM));
			getVomsProxyInfoAndInitPanel();
		}
		return panel;
	}

	/**
	 * @return
	 */
	protected VomsProxyInfoAndInitPanel getVomsProxyInfoAndInitPanel() {
		if (vomsProxyInfoAndInitPanel == null) {
			vomsProxyInfoAndInitPanel = new VomsProxyInfoAndInitPanel();
		}
		return vomsProxyInfoAndInitPanel;
	}

	// remove a listener
	public void removeProxyListener(ProxyInitListener l) {
		getVomsProxyInfoAndInitPanel().removeProxyListener(l);
	}

	/**
	 * Sets the combobox that displays lifetimes
	 * 
	 * @param lifetimes
	 *            a preselection of lifetimes
	 */
	public void setLifetimeDefaults(Integer[] lifetimes) {
		getVomsProxyInfoAndInitPanel().setLifetimeDefaults(lifetimes);
	}

}
