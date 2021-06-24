using System;
using System.Windows.Forms;

namespace PacketEditor
{
    public partial class FrmBurpCode : Form
    {
        public FrmBurpCode(string code)
        {
            InitializeComponent();
            txbBurpCode.Text = code;
        }

        private void btnContinue_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
