import React, { useState } from 'react';
import './UserQuestionModal.css';

function UserQuestionModal({ question, options, context, askId, onRespond, onClose }) {
  const [userInput, setUserInput] = useState('');
  const [selectedOption, setSelectedOption] = useState(null);

  const handleSubmit = () => {
    if (!selectedOption && !userInput.trim()) {
      alert('请选择一个选项或输入您的建议');
      return;
    }

    const response = {
      choice: selectedOption || userInput,
      text: userInput || selectedOption,
      timestamp: Date.now()
    };

    onRespond(askId, response);
  };

  const handleOptionClick = (option) => {
    setSelectedOption(option);
    // 如果选择了选项，清空自定义输入
    if (option !== '其他建议' && option !== '提供建议') {
      setUserInput('');
    }
  };

  return (
    <div className="user-question-overlay">
      <div className="user-question-modal">
        <div className="modal-header">
          <h3>🤖 AI 需要您的意见</h3>
        </div>

        <div className="modal-body">
          {/* 背景信息 */}
          {context && (
            <div className="context-section">
              <h4>📋 当前状态：</h4>
              <pre className="context-content">{context}</pre>
            </div>
          )}

          {/* 问题 */}
          <div className="question-section">
            <h4>❓ 问题：</h4>
            <p className="question-text">{question}</p>
          </div>

          {/* 选项 */}
          <div className="options-section">
            <h4>💡 您的选择：</h4>
            <div className="option-buttons">
              {options.map((option, index) => (
                <button
                  key={index}
                  className={`option-button ${selectedOption === option ? 'selected' : ''}`}
                  onClick={() => handleOptionClick(option)}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>

          {/* 自定义输入 */}
          <div className="custom-input-section">
            <h4>✍️ 或者提供您的建议：</h4>
            <textarea
              className="custom-input"
              placeholder="输入您的建议或指示..."
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              rows={4}
            />
          </div>
        </div>

        <div className="modal-footer">
          <button
            className="submit-button"
            onClick={handleSubmit}
            disabled={!selectedOption && !userInput.trim()}
          >
            提交
          </button>
        </div>
      </div>
    </div>
  );
}

export default UserQuestionModal;
