using System;
using System.Drawing;
using System.Drawing.Design;
using System.Windows.Forms;
using System.Windows.Forms.Design;

namespace Be.Windows.Forms.Design
{
	/// <summary>
	/// Display only fixed-piched fonts
	/// </summary>
	internal class HexFontEditor : FontEditor
	{
		/// <summary>
		/// Edits the value
		/// </summary>
		public override object EditValue(System.ComponentModel.ITypeDescriptorContext context, IServiceProvider provider, object value)
		{
			object tmpValue = value;
			if (provider != null)
			{
				IWindowsFormsEditorService service1 = (IWindowsFormsEditorService) provider.GetService(typeof(IWindowsFormsEditorService));
				if (service1 != null)
				{
                    FontDialog fontDialog = new FontDialog
                    {
                        ShowApply = false,
                        ShowColor = false,
                        AllowVerticalFonts = false,
                        AllowScriptChange = false,
                        FixedPitchOnly = true,
                        ShowEffects = false,
                        ShowHelp = false
                    };

                    if (value is Font font)
                    {
                        fontDialog.Font = font;
                    }
                    if (fontDialog.ShowDialog() == DialogResult.OK)
					{
						tmpValue = fontDialog.Font;
					}

					fontDialog.Dispose();
				}
			}

			value = tmpValue;
            return value;

		}

		public override UITypeEditorEditStyle GetEditStyle(System.ComponentModel.ITypeDescriptorContext context)
		{
			return UITypeEditorEditStyle.Modal;
		}
	}
}
