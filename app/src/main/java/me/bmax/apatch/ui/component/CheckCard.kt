package me.bmax.apatch.ui.component

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Help
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import icu.nullptr.applistdetector.IDetector

@Composable
fun CheckCard(
    title: String,
    result: IDetector.Result?,
    detail: List<Pair<String, IDetector.Result>>?
) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
            .clickable { expanded = !expanded },
        colors = CardDefaults.cardColors(
            containerColor = when (result) {
                IDetector.Result.FOUND -> MaterialTheme.colorScheme.errorContainer
                IDetector.Result.SUSPICIOUS -> MaterialTheme.colorScheme.tertiaryContainer
                IDetector.Result.NOT_FOUND -> MaterialTheme.colorScheme.surfaceVariant
                else -> MaterialTheme.colorScheme.surfaceVariant
            }
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                ResultIcon(result)
            }

            AnimatedVisibility(
                visible = expanded && detail != null,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                Column(
                    modifier = Modifier.padding(top = 8.dp)
                ) {
                    detail?.forEach { (name, itemResult) ->
                        DetailItem(name, itemResult)
                    }
                }
            }
        }
    }
}

@Composable
private fun ResultIcon(result: IDetector.Result?) {
    when (result) {
        IDetector.Result.FOUND -> Icon(
            imageVector = Icons.Filled.Error,
            contentDescription = "Found",
            tint = MaterialTheme.colorScheme.error
        )
        IDetector.Result.SUSPICIOUS -> Icon(
            imageVector = Icons.Filled.Warning,
            contentDescription = "Suspicious",
            tint = MaterialTheme.colorScheme.tertiary
        )
        IDetector.Result.NOT_FOUND -> Icon(
            imageVector = Icons.Filled.CheckCircle,
            contentDescription = "Not Found",
            tint = Color(0xFF4CAF50)
        )
        else -> Icon(
            imageVector = Icons.Filled.Help,
            contentDescription = "Unknown",
            tint = MaterialTheme.colorScheme.outline
        )
    }
}

@Composable
private fun DetailItem(name: String, result: IDetector.Result) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = name,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        when (result) {
            IDetector.Result.FOUND -> Text(
                text = "Found",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
            IDetector.Result.SUSPICIOUS -> Text(
                text = "Suspicious",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.tertiary
            )
            IDetector.Result.NOT_FOUND -> Text(
                text = "Not Found",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF4CAF50)
            )
            else -> Text(
                text = "Unknown",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline
            )
        }
    }
}
