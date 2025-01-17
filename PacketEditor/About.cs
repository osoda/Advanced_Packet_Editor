﻿using System;
using System.Windows.Forms;

namespace PacketEditor
{
    public partial class FrmAbout : Form
    {
        public FrmAbout()
        {
            InitializeComponent();
        }

        private void frmAbout_Load(object sender, EventArgs e)
        {
            string strAbout;
            strAbout = "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n";
            strAbout += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n";
            strAbout += "Advanced Packet Editor 1.5\r\n";
            strAbout += "Written by Israel Chorzevski (Sro - sro.co.il)\r\nAnd Gilad Ofir\n";
            strAbout += "Published by\r\n";
            strAbout += "Under GPL v3 license\r\n";
            strAbout += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n";
            strAbout += "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\r\n";
            strAbout += "Based on packeteditor 0.2.2.1\r\n";
            strAbout += "http://packeteditor.com/";
            strAbout += "\n\nThe Advanced Packet Editor is an Open-Source Project\nFor intercepting and manipulating TCP traffic between Client and Server";

            lblAbout.Text = strAbout;
        }
    }
}
