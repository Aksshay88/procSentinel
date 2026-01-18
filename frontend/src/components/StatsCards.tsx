import React from 'react'
import type { StatsData } from './Dashboard'
import './StatsCards.css'

interface StatsCardsProps {
  stats: StatsData | null
}

const StatsCards: React.FC<StatsCardsProps> = ({ stats }) => {
  if (!stats) {
    return (
      <div className="stats-grid">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="stat-card loading">
            <div className="skeleton-text"></div>
            <div className="skeleton-number"></div>
          </div>
        ))}
      </div>
    )
  }

  const cards = [
    {
      title: 'Total Processes',
      value: stats.total_processes,
      icon: '📊',
      color: '#3b82f6',
      bgColor: 'rgba(59, 130, 246, 0.1)'
    },
    {
      title: 'Normal',
      value: stats.normal,
      icon: '✅',
      color: '#22c55e',
      bgColor: 'rgba(34, 197, 94, 0.1)'
    },
    {
      title: 'Warnings',
      value: stats.warning,
      icon: '⚠️',
      color: '#eab308',
      bgColor: 'rgba(234, 179, 8, 0.1)'
    },
    {
      title: 'Critical',
      value: stats.critical,
      icon: '🚨',
      color: '#ef4444',
      bgColor: 'rgba(239, 68, 68, 0.1)'
    }
  ]

  return (
    <div className="stats-grid">
      {cards.map((card, index) => (
        <div 
          key={index} 
          className="stat-card"
          style={{ 
            borderLeft: `4px solid ${card.color}`,
            background: card.bgColor
          }}
        >
          <div className="stat-header">
            <span className="stat-icon">{card.icon}</span>
            <span className="stat-title">{card.title}</span>
          </div>
          <div className="stat-value" style={{ color: card.color }}>
            {card.value.toLocaleString()}
          </div>
          {card.title === 'Critical' && card.value > 0 && (
            <div className="stat-alert">
              Requires attention
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

export default StatsCards
