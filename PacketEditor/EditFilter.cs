using System;
using System.Data;
using System.Windows.Forms;
using System.Text.RegularExpressions;
using System.Text;

namespace PacketEditor
{
    public partial class EditFilter : Form
    {
        //private bool retVal;
        readonly DataRow drFilters;
        readonly SocketInfo sInfo;
        readonly DataTable dtF; //Forms[Filters].dtFilters
        readonly DataGridView dgF; //Forms[FIlters].dgridFilters
        readonly int dgF_line;

        void UpdateUI(DataRow dr)
        {
            this.txtMsgReplace.TextChanged -= new EventHandler(this.txtMsgReplace_TextChanged);
            this.txtAPIReplace.TextChanged -= new EventHandler(this.txtAPIReplace_TextChanged);
            this.txtDNSReplace.TextChanged -= new EventHandler(this.txtMsgReplace_TextChanged);
            this.cmbMsgActionE.SelectedIndexChanged -= new EventHandler(this.cmbMsgActionE_SelectedIndexChanged);
            this.cmbAPIActionE.SelectedIndexChanged -= new EventHandler(this.cmbAPIActionE_SelectedIndexChanged);
            this.cmbDNSActionE.SelectedIndexChanged -= new EventHandler(this.cmbDNSActionE_SelectedIndexChanged);

            if (dr["id"].ToString() != string.Empty)
            {
                txtName.Text = dr["id"].ToString();
                chkEnabled.Checked = (bool)dr["enabled"];
                foreach (byte b in (byte[])dr["MsgFunction"])
                {
                    chkMsg.SetItemChecked(chkMsg.FindStringExact(sInfo.Msg(b)), true);
                }
                txtMsgCatch.Text = dr["MsgCatch"].ToString();
                switch ((byte)dr["MsgAction"])
                {
                    case Glob.ActionReplaceString:
                        rdoMsgActionR.Checked = true;
                        break;
                    case Glob.ActionReplaceStringH:
                        rdoMsgActionR.Checked = true;
                        rdoMsgMethodH.Checked = true;
                        break;
                    case Glob.ActionError:
                        rdoMsgActionE.Checked = true;
                        break;
                    case Glob.ActionErrorH:
                        rdoMsgActionE.Checked = true;
                        rdoMsgMethodH.Checked = true;
                        break;
                }
                txtMsgReplace.Text = dr["MsgReplace"].ToString();
                cmbMsgActionE.Text = sInfo.Error((int)dr["MsgError"]);
                foreach (byte b in (byte[])dr["APIFunction"])
                {
                    chkAPI.SetItemChecked(chkAPI.FindStringExact(sInfo.Api(b)), true);
                }
                txtAPICatch.Text = dr["APICatch"].ToString();
                switch ((byte)dr["APIAction"])
                {
                    case Glob.ActionReplaceString:
                        rdoAPIActionR.Checked = true;
                        break;
                    case Glob.ActionReplaceStringH:
                        rdoAPIActionR.Checked = true;
                        rdoAPIMethodH.Checked = true;
                        break;
                    case Glob.ActionError:
                        rdoAPIActionE.Checked = true;
                        break;
                    case Glob.ActionErrorH:
                        rdoAPIActionE.Checked = true;
                        rdoAPIMethodH.Checked = true;
                        break;
                }
                txtAPIReplace.Text = dr["APIReplace"].ToString();
                cmbAPIActionE.Text = sInfo.Error((int)dr["APIError"]);
                foreach (byte b in (byte[])dr["DNSFunction"])
                {
                    chkDNS.SetItemChecked(chkDNS.FindStringExact(sInfo.Api(b)), true);
                }
                txtDNSCatch.Text = dr["DNSCatch"].ToString();
                switch ((byte)dr["DNSAction"])
                {
                    case Glob.ActionReplaceString:
                        rdoDNSActionR.Checked = true;
                        break;
                    case Glob.ActionReplaceStringH:
                        rdoDNSActionR.Checked = true;
                        rdoDNSMethodH.Checked = true;
                        break;
                    case Glob.ActionError:
                        rdoDNSActionE.Checked = true;
                        break;
                    case Glob.ActionErrorH:
                        rdoDNSActionE.Checked = true;
                        rdoDNSMethodH.Checked = true;
                        break;
                }
                txtDNSReplace.Text = dr["DNSReplace"].ToString();
                cmbDNSActionE.Text = sInfo.Error((int)dr["DNSError"]);
            }
            else
            {
                cmbMsgActionE.Text = "NO_ERROR";
                cmbAPIActionE.Text = "NO_ERROR";
                cmbDNSActionE.Text = "NO_ERROR";
            }
            this.txtMsgReplace.TextChanged += new EventHandler(this.txtMsgReplace_TextChanged);
            this.txtAPIReplace.TextChanged += new EventHandler(this.txtAPIReplace_TextChanged);
            this.txtDNSReplace.TextChanged += new EventHandler(this.txtMsgReplace_TextChanged);
            this.cmbMsgActionE.SelectedIndexChanged += new EventHandler(this.cmbMsgActionE_SelectedIndexChanged);
            this.cmbAPIActionE.SelectedIndexChanged += new EventHandler(this.cmbAPIActionE_SelectedIndexChanged);
            this.cmbDNSActionE.SelectedIndexChanged += new EventHandler(this.cmbDNSActionE_SelectedIndexChanged);
        }

        void UpdateDR(DataRow dr)
        {
            dr["id"] = txtName.Text;
            dr["enabled"] = chkEnabled.Checked;

            byte[] bytes = new byte[chkMsg.CheckedItems.Count];
            for (int i = 0; i < chkMsg.CheckedItems.Count; i++)
            {
                bytes[i] = sInfo.MsgNum(chkMsg.CheckedItems[i].ToString());
            }
            dr["MsgFunction"] = bytes;
            dr["MsgCatch"] = txtMsgCatch.Text;
            byte t;
            if (rdoMsgActionR.Checked)
                t = Glob.ActionReplaceString;
            else
                t = Glob.ActionError;

            if (rdoMsgMethodH.Checked)
                t++;
            dr["MsgAction"] = t;
            dr["MsgReplace"] = txtMsgReplace.Text;
            dr["MsgError"] = sInfo.ErrorNum(cmbMsgActionE.Text);


            bytes = new byte[chkAPI.CheckedItems.Count];
            for (int i = 0; i < chkAPI.CheckedItems.Count; i++)
            {
                bytes[i] = sInfo.ApiNum(chkAPI.CheckedItems[i].ToString());
            }
            dr["APIFunction"] = bytes;
            dr["APICatch"] = txtAPICatch.Text;

            if (rdoAPIActionR.Checked)
                t = Glob.ActionReplaceString;
            else
                t = Glob.ActionError;

            if (rdoAPIMethodH.Checked)
                t++;

            dr["APIAction"] = t;
            dr["APIReplace"] = txtAPIReplace.Text;
            dr["APIError"] = sInfo.ErrorNum(cmbAPIActionE.Text);


            bytes = new byte[chkDNS.CheckedItems.Count];
            for (int i = 0; i < chkDNS.CheckedItems.Count; i++)
            {
                bytes[i] = sInfo.ApiNum(chkDNS.CheckedItems[i].ToString());
            }
            dr["DNSFunction"] = bytes;
            dr["DNSCatch"] = txtDNSCatch.Text;
            if (rdoDNSActionR.Checked)
                t = Glob.ActionReplaceString;
            else
                t = Glob.ActionError;

            if (rdoDNSMethodH.Checked)
                t++;
            dr["DNSAction"] = t;
            dr["DNSReplace"] = txtDNSReplace.Text;
            dr["DNSError"] = sInfo.ErrorNum(cmbDNSActionE.Text);


            funcUpdate(dr);
        }

        public EditFilter(DataRow dr, SocketInfo si, DataTable dtFilters, DataGridView dgridFilters, int dgF_l)
        {
            InitializeComponent();
            drFilters = dr;
            sInfo = si;
            // the following parameters, need to update the grid of the Filters form
            dtF = dtFilters;
            dgF = dgridFilters; // the grid
            dgF_line = dgF_l; // the line to update

            UpdateUI(dr);
        }

        private void frmEditFilters_Activated(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = 1;
            }
        }

        private void frmEditFilters_Deactivate(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = .5;
            }
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            txtName.Text = txtName.Text.Trim();

            if (txtName.Text != string.Empty)
            {
                if (txtMsgCatch.Text != string.Empty)
                {
                    try
                    {
                        Regex.Match("", txtMsgCatch.Text);
                    }
                    catch (ArgumentException)
                    {
                        tabControl1.SelectedTab = this.tabPage1;
                        txtMsgCatch.Focus();
                        MessageBox.Show("Invalid expression.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if (txtAPICatch.Text != string.Empty)
                {
                    try
                    {
                        Regex.Match("", txtAPICatch.Text);
                    }
                    catch (ArgumentException)
                    {
                        tabControl1.SelectedTab = this.tabPage2;
                        txtAPICatch.Focus();
                        MessageBox.Show("Invalid expression.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if (txtDNSCatch.Text != string.Empty)
                {
                    try
                    {
                        Regex.Match("", txtDNSCatch.Text);
                    }
                    catch (ArgumentException)
                    {
                        tabControl1.SelectedTab = this.tabPage3;
                        txtDNSCatch.Focus();
                        MessageBox.Show("Invalid expression.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                Form fc = Application.OpenForms["Filters"];
                if (fc != null)
                {
                    UpdateDR(drFilters);
                }
                this.Close();
            }
            else
            {
                MessageBox.Show("You must enter a filter name.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtName.Focus();
            }
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            //retVal = false;
            this.Close();
        }

        private void txtMsgReplace_TextChanged(object sender, EventArgs e)
        {
            if (!rdoMsgActionR.Checked)
                rdoMsgActionR.Checked = true;
        }

        private void txtAPIReplace_TextChanged(object sender, EventArgs e)
        {
            if (!rdoAPIActionR.Checked)
                rdoAPIActionR.Checked = true;
        }

        private void txtDNSReplace_TextChanged(object sender, EventArgs e)
        {
            if (!rdoDNSActionR.Checked)
                rdoDNSActionR.Checked = true;
        }

        private void cmbMsgActionE_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (!rdoMsgActionE.Checked)
                rdoMsgActionE.Checked = true;
        }

        private void cmbAPIActionE_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (!rdoAPIActionE.Checked)
                rdoAPIActionE.Checked = true;
        }

        private void cmbDNSActionE_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (!rdoDNSActionE.Checked)
                rdoDNSActionE.Checked = true;
        }

        private void funcUpdate(DataRow dr)
        {
            int idx = dgF_line;
            if (dtF.Rows.Find(dr["id"].ToString()) == null) // new one
            {
                dtF.Rows.Add(dr);
                idx = dgF.Rows.Add();
            }
            dgF.Rows[idx].Cells["name"].Value = dr["id"].ToString();
            dgF.Rows[idx].Cells["enabled"].Value = dr["enabled"];
            
            StringBuilder funs = new StringBuilder();
            foreach (byte f in (byte[])dr["MsgFunction"])
            {
                funs.Append(sInfo.Msg(f) + " ");
            }
            foreach (byte f in (byte[])dr["APIFunction"])
            {
                funs.Append(sInfo.Api(f) + " ");
            }
            foreach (byte f in (byte[])dr["DNSFunction"])
            {
                funs.Append(sInfo.Api(f) + " ");
            }

            if (funs.ToString() != string.Empty)
            {
                dgF.Rows[idx].Cells["function"].Value = funs.ToString().TrimEnd();
            }
        }

        private void btnApply_Click(object sender, EventArgs e)
        {
            // exactly like btnOk just without this.Close
            txtName.Text = txtName.Text.Trim();

            if (txtName.Text != string.Empty)
            {
                if (txtMsgCatch.Text != string.Empty)
                {
                    try
                    {
                        Regex.Match("", txtMsgCatch.Text);
                    }
                    catch (ArgumentException)
                    {
                        tabControl1.SelectedTab = this.tabPage1;
                        txtMsgCatch.Focus();
                        MessageBox.Show("Invalid expression.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if (txtAPICatch.Text != string.Empty)
                {
                    try
                    {
                        Regex.Match("", txtAPICatch.Text);
                    }
                    catch (ArgumentException)
                    {
                        tabControl1.SelectedTab = this.tabPage2;
                        txtAPICatch.Focus();
                        MessageBox.Show("Invalid expression.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                if (txtDNSCatch.Text != string.Empty)
                {
                    try
                    {
                        Regex.Match("", txtDNSCatch.Text);
                    }
                    catch (ArgumentException)
                    {
                        tabControl1.SelectedTab = this.tabPage3;
                        txtDNSCatch.Focus();
                        MessageBox.Show("Invalid expression.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        return;
                    }
                }

                Form fc = Application.OpenForms["Filters"];
                if (fc != null) // if the form is open
                {
                    UpdateDR(drFilters);
                }
            }
            else
            {
                MessageBox.Show("You must enter a filter name.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtName.Focus();
            }
        }
    }
}
