using System;
using System.ComponentModel;
using System.Windows.Forms;
using System.Diagnostics;
using System.Linq;

namespace PacketEditor
{
    public partial class Attach : Form
    {
        private static readonly NLog.Logger logger = NLog.LogManager.GetCurrentClassLogger();

        public int PID { get; private set; }
        public string ProcPath { get; private set; } = "";

        public Attach()
        {
            InitializeComponent();
        }

        private void frmAttach_Load(object sender, EventArgs e)
        {
            AddGridViewItems();
            //int idx = 0;
            //bool contains = false;

            //foreach (Process theprocess in Process.GetProcesses())
            //{
            //    foreach (DataGridViewRow r in dgridAttach.Rows)
            //    {
            //        if (r.Cells["name"].Value.ToString() == theprocess.ProcessName)
            //        {
            //            contains = true;
            //            break;
            //        }
            //    }
            //    if (contains)
            //    {
            //        contains = false;
            //        continue;
            //    }

            //    dgridAttach.Rows.Add();
            //    dgridAttach.Rows[idx].Selected = false;
            //    dgridAttach.Rows[idx].Cells["id"].Value = theprocess.Id.ToString("X8");
            //    dgridAttach.Rows[idx].Cells["name"].Value = theprocess.ProcessName;
            //    dgridAttach.Rows[idx].Cells["window"].Value = theprocess.MainWindowTitle;
            //    try
            //    {
            //        dgridAttach.Rows[idx].Cells["path"].Value = theprocess.MainModule.FileName;
            //    }
            //    catch { }

            //    if (dgridAttach.Rows[idx].Cells["path"].Value == null)
            //        dgridAttach.Rows[idx].Cells["path"].Value = theprocess.StartInfo.FileName;

            //    if (dgridAttach.Rows[idx].Cells["path"].Value.ToString() == string.Empty)
            //        dgridAttach.Rows.Remove(dgridAttach.Rows[idx]);
            //    else
            //        idx++;
            //}

            //dgridAttach.Sort(dgridAttach.Columns["name"], ListSortDirection.Descending);
        }

        void AddGridViewItems()
        {
            Process[] processList = Process.GetProcesses();
            var dgvRows = dgridAttach.Rows.Cast<DataGridViewRow>();

            var procsNotInGridView = from proc in processList
                                join row in dgvRows on proc.ProcessName equals row.Cells["name"].Value.ToString() into contained
                                where !contained.Any()
                                select proc;

            foreach (Process proc in procsNotInGridView)
            {
                int idx = dgridAttach.Rows.Add();
                dgridAttach.Rows[idx].Selected = false;
                dgridAttach.Rows[idx].Cells["id"].Value = proc.Id.ToString("X8");
                dgridAttach.Rows[idx].Cells["name"].Value = proc.ProcessName;
                dgridAttach.Rows[idx].Cells["window"].Value = proc.MainWindowTitle;
                try
                {
                    dgridAttach.Rows[idx].Cells["path"].Value = proc.MainModule.FileName;
                }
                catch (Win32Exception)
                {
                    dgridAttach.Rows[idx].Cells["path"].Value = proc.StartInfo.FileName;
                }
                catch (Exception ex)
                {
                    logger.Error(ex, "Get Process.MainModule failed");
                }

                if (dgridAttach.Rows[idx].Cells["path"].Value.ToString() == string.Empty)
                    dgridAttach.Rows.Remove(dgridAttach.Rows[idx]);
            }

            dgridAttach.Sort(dgridAttach.Columns["name"], ListSortDirection.Ascending);
        }

        void CloseForm()
        {
            Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            CloseForm();
        }

        private void btnAttach_Click(object sender, EventArgs e)
        {
            if (dgridAttach.SelectedRows.Count != 0)
            {
                PID = int.Parse(dgridAttach.SelectedRows[0].Cells["id"].Value.ToString(), System.Globalization.NumberStyles.HexNumber);
                ProcPath = dgridAttach.SelectedRows[0].Cells["path"].Value.ToString();
                CloseForm();
            }
            else
            {
                MessageBox.Show(this, "You must select a process.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void dgridAttach_KeyPress(object sender, KeyPressEventArgs e)
        {
            if (e.KeyChar == (char)Keys.Escape)
            {
                CloseForm();
            }

            if (char.IsLetterOrDigit(e.KeyChar))
            {
                foreach (DataGridViewRow dgvRow in dgridAttach.Rows)
                {
                    if (dgvRow.Cells["name"].FormattedValue.ToString().StartsWith(e.KeyChar.ToString(),
                        true,
                        System.Globalization.CultureInfo.InvariantCulture))
                    {
                        dgvRow.Selected = true;
                        break;
                    }
                }
            }
        }

        private void frmAttach_Activated(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = 1;
            }
        }

        private void frmAttach_Deactivate(object sender, EventArgs e)
        {
            if (this.TopMost)
            {
                this.Opacity = .5;
            }
        }
    }
}
