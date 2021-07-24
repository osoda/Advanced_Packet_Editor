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
        readonly DataTable dtF; //Forms[Filters].dtFilters
        readonly DataGridView dgF; //Forms[FIlters].dgridFilters
        readonly int dgF_line;

        public EditFilter(DataRow dr, DataTable dtFilters, DataGridView dgridFilters, int dgF_l)
        {
            InitializeComponent();

            drFilters = dr;
            // the following parameters, need to update the grid of the Filters form
            dtF = dtFilters;
            dgF = dgridFilters; // the grid
            dgF_line = dgF_l; // the line to update

            UpdateUI(dr);
        }

        void UpdateUI(DataRow dr)
        {
            #region Remove controls EventHandler
            this.txtMsgReplace.TextChanged -= txtMsgReplace_TextChanged;
            this.txtAPIReplace.TextChanged -= txtAPIReplace_TextChanged;
            this.txtDNSReplace.TextChanged -= txtMsgReplace_TextChanged;
            this.cmbMsgActionE.SelectedIndexChanged -= cmbMsgActionE_SelectedIndexChanged;
            this.cmbAPIActionE.SelectedIndexChanged -= cmbAPIActionE_SelectedIndexChanged;
            this.cmbDNSActionE.SelectedIndexChanged -= cmbDNSActionE_SelectedIndexChanged;
            #endregion

            if (dr["id"].ToString() != string.Empty)
            {
                txtName.Text = dr["id"].ToString();
                chkEnabled.Checked = (bool)dr["enabled"];

                #region Msg
                foreach (byte b in (byte[])dr["MsgFunction"])
                {
                    chkMsg.SetItemChecked(chkMsg.FindStringExact(SocketInfoUtils.Msg(b)), true);
                }
                txtMsgCatch.Text = dr["MsgCatch"].ToString();
                switch ((Action)dr["MsgAction"])
                {
                    case Action.ReplaceString:
                        rdoMsgActionR.Checked = true;
                        break;
                    case Action.ReplaceStringHex:
                        rdoMsgActionR.Checked = true;
                        rdoMsgMethodH.Checked = true;
                        break;
                    case Action.Error:
                        rdoMsgActionE.Checked = true;
                        break;
                    case Action.ErrorHex:
                        rdoMsgActionE.Checked = true;
                        rdoMsgMethodH.Checked = true;
                        break;
                }
                txtMsgReplace.Text = dr["MsgReplace"].ToString();
                cmbMsgActionE.Text = SocketInfoUtils.Error((int)dr["MsgError"]);
                #endregion

                #region API
                foreach (byte b in (byte[])dr["APIFunction"])
                {
                    chkAPI.SetItemChecked(chkAPI.FindStringExact(SocketInfoUtils.Api(b)), true);
                }
                txtAPICatch.Text = dr["APICatch"].ToString();
                switch ((Action)dr["APIAction"])
                {
                    case Action.ReplaceString:
                        rdoAPIActionR.Checked = true;
                        break;
                    case Action.ReplaceStringHex:
                        rdoAPIActionR.Checked = true;
                        rdoAPIMethodH.Checked = true;
                        break;
                    case Action.Error:
                        rdoAPIActionE.Checked = true;
                        break;
                    case Action.ErrorHex:
                        rdoAPIActionE.Checked = true;
                        rdoAPIMethodH.Checked = true;
                        break;
                }
                txtAPIReplace.Text = dr["APIReplace"].ToString();
                cmbAPIActionE.Text = SocketInfoUtils.Error((int)dr["APIError"]);
                #endregion

                #region DNS
                foreach (byte b in (byte[])dr["DNSFunction"])
                {
                    chkDNS.SetItemChecked(chkDNS.FindStringExact(SocketInfoUtils.Api(b)), true);
                }
                txtDNSCatch.Text = dr["DNSCatch"].ToString();
                switch ((Action)dr["DNSAction"])
                {
                    case Action.ReplaceString:
                        rdoDNSActionR.Checked = true;
                        break;
                    case Action.ReplaceStringHex:
                        rdoDNSActionR.Checked = true;
                        rdoDNSMethodH.Checked = true;
                        break;
                    case Action.Error:
                        rdoDNSActionE.Checked = true;
                        break;
                    case Action.ErrorHex:
                        rdoDNSActionE.Checked = true;
                        rdoDNSMethodH.Checked = true;
                        break;
                }
                txtDNSReplace.Text = dr["DNSReplace"].ToString();
                cmbDNSActionE.Text = SocketInfoUtils.Error((int)dr["DNSError"]);
            }
            else
            {
                cmbMsgActionE.Text = "NO_ERROR";
                cmbAPIActionE.Text = "NO_ERROR";
                cmbDNSActionE.Text = "NO_ERROR";
            }
            #endregion

            #region Reasign controls EventHandler
            this.txtMsgReplace.TextChanged += txtMsgReplace_TextChanged;
            this.txtAPIReplace.TextChanged += txtAPIReplace_TextChanged;
            this.txtDNSReplace.TextChanged += txtMsgReplace_TextChanged;
            this.cmbMsgActionE.SelectedIndexChanged += cmbMsgActionE_SelectedIndexChanged;
            this.cmbAPIActionE.SelectedIndexChanged += cmbAPIActionE_SelectedIndexChanged;
            this.cmbDNSActionE.SelectedIndexChanged += cmbDNSActionE_SelectedIndexChanged;
            #endregion
        }

        void UpdateDR(DataRow dr)
        {
            dr["id"] = txtName.Text;
            dr["enabled"] = chkEnabled.Checked;

            #region Msg
            byte[] bytes = new byte[chkMsg.CheckedItems.Count];
            for (int i = 0; i < chkMsg.CheckedItems.Count; i++)
            {
                bytes[i] = SocketInfoUtils.MsgNum(chkMsg.CheckedItems[i].ToString());
            }
            dr["MsgFunction"] = bytes;
            dr["MsgCatch"] = txtMsgCatch.Text;
            byte actionByte;
            if (rdoMsgActionR.Checked)
                actionByte = (byte)Action.ReplaceString;
            else
                actionByte = (byte)Action.Error;

            if (rdoMsgMethodH.Checked)
                actionByte++;

            dr["MsgAction"] = actionByte;
            dr["MsgReplace"] = txtMsgReplace.Text;
            dr["MsgError"] = SocketInfoUtils.ErrorNum(cmbMsgActionE.Text);
            #endregion

            #region API
            bytes = new byte[chkAPI.CheckedItems.Count];
            for (int i = 0; i < chkAPI.CheckedItems.Count; i++)
            {
                bytes[i] = SocketInfoUtils.ApiNum(chkAPI.CheckedItems[i].ToString());
            }
            dr["APIFunction"] = bytes;
            dr["APICatch"] = txtAPICatch.Text;

            if (rdoAPIActionR.Checked)
                actionByte = (byte)Action.ReplaceString;
            else
                actionByte = (byte)Action.Error;

            if (rdoAPIMethodH.Checked)
                actionByte++;

            dr["APIAction"] = actionByte;
            dr["APIReplace"] = txtAPIReplace.Text;
            dr["APIError"] = SocketInfoUtils.ErrorNum(cmbAPIActionE.Text);
            #endregion

            #region DNS
            bytes = new byte[chkDNS.CheckedItems.Count];
            for (int i = 0; i < chkDNS.CheckedItems.Count; i++)
            {
                bytes[i] = SocketInfoUtils.ApiNum(chkDNS.CheckedItems[i].ToString());
            }
            dr["DNSFunction"] = bytes;
            dr["DNSCatch"] = txtDNSCatch.Text;
            if (rdoDNSActionR.Checked)
                actionByte = (byte)Action.ReplaceString;
            else
                actionByte = (byte)Action.Error;

            if (rdoDNSMethodH.Checked)
                actionByte++;

            dr["DNSAction"] = actionByte;
            dr["DNSReplace"] = txtDNSReplace.Text;
            dr["DNSError"] = SocketInfoUtils.ErrorNum(cmbDNSActionE.Text);
            #endregion

            FuncUpdate(dr);
        }

        private void CloseForm()
        {
            Close();
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

        /// <summary>
        /// Validate the TextBox.Text is a valid regular expression or not.
        /// If not, it will show up a MessageBox to warn user.
        /// </summary>
        /// <param name="textBox"></param>
        /// <param name="tabPage">The textBox layout tab</param>
        /// <returns><c>true</c> if it is a valid regular expression; otherwise, <c>false</c>.</returns>
        private bool ValidateRegex(in TextBox textBox, in TabPage tabPage)
        {
            if (textBox.Text == string.Empty)
            {
                return true;
            }

            try
            {
                Regex.Match("", textBox.Text);
            }
            catch (ArgumentException)
            {
                tabControl1.SelectedTab = tabPage;
                textBox.Focus();
                MessageBox.Show("Invalid regular expression in Catch section.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
            return true;
        }

        private void btnOK_Click(object sender, EventArgs e)
        {
            txtName.Text = txtName.Text.Trim();

            if (txtName.Text != string.Empty)
            {
                if (!ValidateRegex(txtMsgCatch, tabPage1))
                {
                    return;
                }

                if (!ValidateRegex(txtAPICatch, tabPage2))
                {
                    return;
                }

                if (!ValidateRegex(txtDNSCatch, tabPage3))
                {
                    return;
                }

                Form fc = Application.OpenForms["Filters"];
                if (fc != null)
                {
                    UpdateDR(drFilters);
                }
                CloseForm();
            }
            else
            {
                MessageBox.Show("You must enter a filter name.", "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
                txtName.Focus();
            }
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            CloseForm();
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

        private void FuncUpdate(DataRow dr)
        {
            int idx = dgF_line;
            if (dtF.Rows.Find(dr["id"].ToString()) == null) // new one
            {
                dtF.Rows.Add(dr);
                idx = dgF.Rows.Add();
            }
            dgF.Rows[idx].Cells["name"].Value = dr["id"].ToString();
            dgF.Rows[idx].Cells["enabled"].Value = dr["enabled"];

            var funs = new StringBuilder();
            foreach (byte f in (byte[])dr["MsgFunction"])
            {
                funs.Append(SocketInfoUtils.Msg(f) + " ");
            }
            foreach (byte f in (byte[])dr["APIFunction"])
            {
                funs.Append(SocketInfoUtils.Api(f) + " ");
            }
            foreach (byte f in (byte[])dr["DNSFunction"])
            {
                funs.Append(SocketInfoUtils.Api(f) + " ");
            }

            if (funs.Length != 0)
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
                if (!ValidateRegex(txtMsgCatch, tabPage1))
                {
                    return;
                }

                if (!ValidateRegex(txtAPICatch, tabPage2))
                {
                    return;
                }

                if (!ValidateRegex(txtDNSCatch, tabPage3))
                {
                    return;
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
