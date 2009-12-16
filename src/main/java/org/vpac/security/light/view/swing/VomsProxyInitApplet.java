package org.vpac.security.light.view.swing;

import java.awt.BorderLayout;

import javax.swing.JApplet;

public class VomsProxyInitApplet extends JApplet {

	private VomsProxyInfoAndInitPanel vomsProxyInfoAndInitPanel;

	/**
	 * Create the applet
	 */
	public VomsProxyInitApplet() {
		super();
		getContentPane().add(getVomsProxyInfoAndInitPanel(),
				BorderLayout.CENTER);
		//
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

}
