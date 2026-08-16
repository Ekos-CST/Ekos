package com.ekos.antivirus

import android.content.Intent
import android.net.Uri
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.RecyclerView
import com.ekos.antivirus.engine.ScannedAppItem
import com.ekos.antivirus.engine.ThreatSeverity

class ScannedAppAdapter(
    private val items: List<ScannedAppItem>
) : RecyclerView.Adapter<ScannedAppAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val ivIcon: ImageView = view.findViewById(R.id.ivAppIcon)
        val tvName: TextView = view.findViewById(R.id.tvAppName)
        val tvPackage: TextView = view.findViewById(R.id.tvAppPackage)
        val tvThreat: TextView = view.findViewById(R.id.tvThreatDetails)
        val tvBadge: TextView = view.findViewById(R.id.tvAppStatusBadge)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_scanned_app, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.tvName.text = item.appName
        holder.tvPackage.text = item.packageName

        if (item.icon != null) {
            holder.ivIcon.setImageDrawable(item.icon)
        } else {
            holder.ivIcon.setImageResource(R.mipmap.ic_launcher)
        }

        when (item.severity) {
            ThreatSeverity.SAFE -> {
                holder.tvBadge.text = "GÜVENLİ"
                holder.tvBadge.setTextColor(ContextCompat.getColor(holder.itemView.context, R.color.status_green_light))
                holder.tvThreat.visibility = View.GONE
            }
            ThreatSeverity.SUSPICIOUS -> {
                holder.tvBadge.text = "ŞÜPHELİ"
                holder.tvBadge.setTextColor(ContextCompat.getColor(holder.itemView.context, R.color.status_amber_light))
                holder.tvThreat.text = item.riskDetails ?: "Şüpheli izin veya imza"
                holder.tvThreat.visibility = View.VISIBLE
            }
            ThreatSeverity.MALICIOUS -> {
                holder.tvBadge.text = "TEHDİT"
                holder.tvBadge.setTextColor(ContextCompat.getColor(holder.itemView.context, R.color.status_red_light))
                holder.tvThreat.text = "${item.threatName}: ${item.riskDetails ?: "Zararlı yazılım tespiti"}"
                holder.tvThreat.visibility = View.VISIBLE
            }
        }

        holder.itemView.setOnClickListener {
            if (item.severity != ThreatSeverity.SAFE && !item.isSystemApp) {
                val uninstallIntent = Intent(Intent.ACTION_UNINSTALL_PACKAGE).apply {
                    data = Uri.parse("package:${item.packageName}")
                    putExtra(Intent.EXTRA_RETURN_RESULT, true)
                }
                holder.itemView.context.startActivity(uninstallIntent)
            }
        }
    }

    override fun getItemCount(): Int = items.size
}
