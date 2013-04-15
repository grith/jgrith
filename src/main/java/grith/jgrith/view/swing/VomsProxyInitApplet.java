package grith.jgrith.view.swing;

import grith.jgrith.voms.VOManagement.VOManager;

import java.awt.BorderLayout;

import javax.swing.JApplet;

public class VomsProxyInitApplet extends JApplet {

	private VomsProxyInfoAndInitPanel vomsProxyInfoAndInitPanel;
	private final VOManager vom;

	/**
	 * Create the applet
	 */
	public VomsProxyInitApplet(VOManager vom) {
		super();
		this.vom = vom;
		getContentPane().add(getVomsProxyInfoAndInitPanel(),
				BorderLayout.CENTER);
		//
	}

	/**
	 * @return
	 */
	protected VomsProxyInfoAndInitPanel getVomsProxyInfoAndInitPanel() {
		if (vomsProxyInfoAndInitPanel == null) {
			vomsProxyInfoAndInitPanel = new VomsProxyInfoAndInitPanel(vom);
		}
		return vomsProxyInfoAndInitPanel;
	}

}
